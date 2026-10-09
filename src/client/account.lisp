;;;; account.lisp — one Marmot account: identity, relays, KeyPackages, groups
;;;;
;;;; This is the orchestration layer: it owns a relay POOL and drives the
;;;; transport flows of transports/nostr.md around the protocol code in
;;;; marmot/groups.lisp.  Everything is synchronous; SYNC fetches what is new
;;;; and processes it, so a REPL user or a script decides when the network is
;;;; touched.

(in-package #:cl-marmot)

(defstruct account
  sk pubkey
  (relays '())                         ; our NIP-65 / inbox / KeyPackage relays
  (pools (make-hash-table :test #'equal))   ; relay-set key -> cl-nostr pool
  (key-packages '())                   ; list of plists (:bundle :event-id :ref :d)
  (groups (make-hash-table :test #'equal))   ; MLS group id hex -> MARMOT-GROUP
  (seen-wraps (make-hash-table :test #'equal))
  (seen-group-events (make-hash-table :test #'equal))
  (last-sync 0)
  (outbox '())                         ; Welcome deliveries still owed (plists), see QUEUE-WELCOMES
  (unsaved-messages '())               ; (group-id-hex . message-plist), newest first, for the log
  (last-saved nil)                     ; the account text last written (to skip unchanged saves)
  (last-kp-check 0)                    ; when KeyPackage upkeep last ran (in-memory)
  (checkpoint nil)                     ; (lambda ()) that saves the account; called before publishing
  (on-event nil))                      ; (lambda (account group result)) for UIs

(defun %checkpoint (acct)
  "Persist the account now: a commit or Welcome must be on disk before its
bytes can be on the wire (publish-lifecycle.md 'Restart')."
  (when (account-checkpoint acct) (funcall (account-checkpoint acct))))

(defun account-pubkey-hex (acct) (octets->hex (account-pubkey acct)))
(defun account-npub (acct) (npub-encode (account-pubkey acct)))

(defun make-account-from-secret (sk &key relays)
  (make-account :sk sk :pubkey (secp256k1-xonly-pubkey sk) :relays relays))

(defun new-account (&key relays)
  (make-account-from-secret (generate-nostr-key) :relays relays))

;;; Relays: one cl-nostr pool per relay set, created on first use.  A publish
;;; succeeds when at least one relay ACKs (publish-lifecycle.md); results come
;;; back as (url accepted message) per relay, unreachable relays included.

(defparameter *relay-timeout* 8 "Seconds to wait for relay ACKs / EOSE.")

(defun %pool-for (acct urls)
  (let* ((urls (sort (remove-duplicates (copy-list urls) :test #'string=) #'string<))
         (key (format nil "~{~A~^ ~}" urls)))
    (or (gethash key (account-pools acct))
        (setf (gethash key (account-pools acct)) (pool:make-pool urls :timeout *relay-timeout*)))))

(defun close-account-pools (acct)
  (loop for p being the hash-values of (account-pools acct) do (ignore-errors (pool:close-pool p)))
  (clrhash (account-pools acct)))

(defun pool-publish* (acct urls ev)
  (mapcar (lambda (ack) (list (pool:ack-url ack) (pool:ack-accepted-p ack) (pool:ack-message ack)))
          (pool:pool-publish-sync (%pool-for acct urls) ev :timeout *relay-timeout*)))

(defun publish-accepted-p (results) (some #'second results))

(defun pool-query (acct urls filters)
  "Stored events matching FILTERS on URLS, each one verified (id + signature)."
  (remove-if-not #'verify-event
                 (pool:fetch-events (%pool-for acct urls) filters :timeout *relay-timeout*)))

(defun %publish (acct urls ev &key (require t))
  (let ((results (pool-publish* acct urls ev)))
    (when (and require (not (publish-accepted-p results)))
      (marmot-fail "no relay accepted kind ~D: ~S" (ev:event-kind ev) results))
    results))

(defparameter *lookup-relays* '("wss://purplepag.es" "wss://relay.damus.io" "wss://nos.lol"
                                "wss://relay.primal.net")
  "Directory relays for other accounts' relay lists, in addition to our own.
Publication of our own relay lists also goes here so others can find them.
Only used by accounts whose relays are all public (wss://): a local ws://
setup (tests, development) never touches public infrastructure.")

(defun %lookup-relays (acct)
  (let ((own (account-relays acct)))
    (if (and own (every (lambda (r) (and (> (length r) 6) (string-equal "wss://" r :end2 6))) own))
        (remove-duplicates (append own *lookup-relays*) :test #'string=)
        own)))

;;; ---------------------------------------------------------------------------
;;; Account preparation (transports/nostr.md "Migration from kind 10051")

(defun publish-relay-lists (acct)
  (%publish acct (%lookup-relays acct) (relay-list-event (account-sk acct) 10002 (account-relays acct)))
  (%publish acct (%lookup-relays acct) (relay-list-event (account-sk acct) 10050 (account-relays acct))))

(defun publish-profile (acct name)
  (%publish acct (account-relays acct)
            (make-signed-event (account-sk acct) :kind 0 :content (to-json (jobj "name" name "display_name" name)))))

(defun publish-key-package (acct &key (d (random-octets 32)))
  "Create and publish a fresh KeyPackage in slot D.  Returns its plist."
  (let* ((bundle (make-marmot-key-package (account-sk acct)))
         (ev (key-package-event (account-sk acct) bundle d))
         (entry (list :bundle bundle :event-id (ev:event-id ev)
                      :ref (octets->hex (key-package-ref (key-package-bundle-key-package bundle)))
                      :d d)))
    (%publish acct (account-relays acct) ev)
    (push entry (account-key-packages acct))
    entry))

(defun setup-account (acct &key name)
  (publish-relay-lists acct)
  (when name (publish-profile acct name))
  (publish-key-package acct))

;;; KeyPackage upkeep (foundation/key-packages.md "Selection and lifecycle")

(defparameter *kp-refresh-window* (* 7 24 3600)
  "Publish a replacement when no KeyPackage of ours is valid this much longer.")

(defun %kp-not-after (entry)
  (lifetime-not-after (leaf-node-lifetime (key-package-leaf-node
                                           (key-package-bundle-key-package (getf entry :bundle))))))

(defun key-package-plan (acct now)
  "Returns (values expired-entries refresh-needed-p slot): entries past their
lifetime (their private keys must go), whether a fresh KeyPackage is due, and
the publication slot (d) to reuse for it."
  (let* ((entries (account-key-packages acct))
         (expired (remove-if-not (lambda (e) (< (%kp-not-after e) now)) entries))
         (live (set-difference entries expired))
         (newest (first (sort (copy-list entries) #'> :key #'%kp-not-after))))
    (values expired
            (notany (lambda (e) (> (%kp-not-after e) (+ now *kp-refresh-window*))) live)
            (and newest (getf newest :d)))))

(defun maintain-key-packages (acct &key (now (unix-time)) force)
  "At most hourly (or when FORCE): delete expired KeyPackage keys and publish a
replacement when ours are about to run out.  After a replacement is
confirmed, older KeyPackages in that slot are dropped with their keys."
  (when (or force (> now (+ (account-last-kp-check acct) 3600)))
    (setf (account-last-kp-check acct) now)
    (multiple-value-bind (expired refresh slot) (key-package-plan acct now)
      (setf (account-key-packages acct) (set-difference (account-key-packages acct) expired))
      (when refresh
        (let* ((old (remove-if-not (lambda (e) (and slot (octets= (getf e :d) slot))) (account-key-packages acct)))
               (new (handler-case (publish-key-package acct :d (or slot (random-octets 32)))
                      (error (c) (warn "KeyPackage refresh failed: ~A" c) nil))))
          (when new
            (setf (account-key-packages acct) (set-difference (account-key-packages acct) old))
            (%checkpoint acct)))))))

;;; ---------------------------------------------------------------------------
;;; Directory lookups

(defun %latest (events)
  (first (sort (copy-list events) (lambda (a b)
                                    (or (> (ev:event-created-at a) (ev:event-created-at b))
                                        (and (= (ev:event-created-at a) (ev:event-created-at b))
                                             (string< (ev:event-id a) (ev:event-id b))))))))

(defun fetch-relay-list (acct pubkey-hex kind &key (lookup-relays (%lookup-relays acct)))
  (let ((ev (%latest (remove-if-not (lambda (e) (string= (ev:event-pubkey e) pubkey-hex))
                                    (pool-query acct lookup-relays
                                                (list (flt:make-filter :kinds (list kind) :authors (list pubkey-hex))))))))
    (and ev (if (= kind 10002) (nip65-write-relays ev) (nip17-inbox-relays ev)))))

(defun fetch-key-package (acct pubkey-hex)
  "Fetch, validate and choose one KeyPackage for PUBKEY-HEX.  Returns
(values key-package event)."
  (let* ((relays (or (fetch-relay-list acct pubkey-hex 10002)
                     (marmot-fail "~A has no NIP-65 relay list" pubkey-hex)))
         (events (pool-query acct relays
                             (list (flt:make-filter :kinds '(30443) :authors (list pubkey-hex)))))
         (slots (make-hash-table :test #'equal)))
    ;; newest per (author, d) slot
    (dolist (ev events)
      (when (string= (ev:event-pubkey ev) pubkey-hex)
        (let ((d (ignore-errors (event-tag-value ev "d"))))
          (when d (setf (gethash d slots) (%latest (cons ev (let ((x (gethash d slots))) (and x (list x))))))))))
    (let ((valid '()))
      (loop for ev being the hash-values of slots
            do (handler-case (push (cons (validate-key-package-event ev) ev) valid)
                 (error () nil)))
      (unless valid (marmot-fail "no valid KeyPackage for ~A" pubkey-hex))
      ;; prefer non-last-resort, then freshest, then lowest KeyPackageRef
      (let ((best (first (sort valid
                               (lambda (a b)
                                 (let ((la (key-package-last-resort-p (car a)))
                                       (lb (key-package-last-resort-p (car b))))
                                   (cond ((and (not la) lb) t)
                                         ((and la (not lb)) nil)
                                         ((/= (ev:event-created-at (cdr a)) (ev:event-created-at (cdr b)))
                                          (> (ev:event-created-at (cdr a)) (ev:event-created-at (cdr b))))
                                         (t (octets< (key-package-ref (car a)) (key-package-ref (car b)))))))))))
        (values (car best) (cdr best))))))

;;; ---------------------------------------------------------------------------
;;; Welcomes

(defun process-gift-wrap (acct wrap)
  "Returns the new MARMOT-GROUP if WRAP was a Welcome we could join."
  (when (gethash (ev:event-id wrap) (account-seen-wraps acct))
    (return-from process-gift-wrap nil))
  (setf (gethash (ev:event-id wrap) (account-seen-wraps acct)) (ev:event-created-at wrap))
  (let ((rumor (handler-case (gift-unwrap wrap (account-sk acct))
                 (error (c) (warn "gift wrap ~A: ~A" (ev:event-id wrap) c) nil))))
    (when (and rumor (= (ev:event-kind rumor) 444))
      (multiple-value-bind (welcome kp-event-id relays) (welcome-rumor-parts rumor)
        (declare (ignore relays))
        (let ((entry (find-if (lambda (e)
                                (find (hex->octets (getf e :ref)) (welcome-secrets welcome)
                                      :key #'encrypted-group-secrets-new-member :test #'octets=))
                              (account-key-packages acct))))
          (unless entry
            (warn "Welcome ~A references no KeyPackage of ours (e=~A)" (ev:event-id rumor) kp-event-id)
            (return-from process-gift-wrap nil))
          (let ((mg (handler-case (join-marmot-group welcome (getf entry :bundle))
                      (marmot-error (c) (warn "rejected Welcome: ~A" (marmot-error-message c)) nil))))
            (when mg
              (when (gethash (mg-id-hex mg) (account-groups acct))
                (warn "Welcome for a group we already have; ignored")
                (return-from process-gift-wrap nil))
              (setf (gethash (mg-id-hex mg) (account-groups acct)) mg)
              (%note mg :type :joined :epoch (mg-epoch mg)
                        :inviter (ev:event-pubkey rumor))
              ;; key-packages.md: publish a replacement in the same slot; the
              ;; consumed init_key is deleted once the replacement is confirmed
              ;; (a single-use package is spent either way)
              (let ((replaced (handler-case (progn (publish-key-package acct :d (getf entry :d)) t)
                                (error (c) (warn "KeyPackage rotation failed: ~A" c) nil))))
                (when (or replaced
                          (not (key-package-last-resort-p (key-package-bundle-key-package (getf entry :bundle)))))
                  (setf (account-key-packages acct) (remove entry (account-key-packages acct)))))
              (when (account-on-event acct)
                (funcall (account-on-event acct) acct mg (list :type :joined)))
              mg)))))))

;;; ---------------------------------------------------------------------------
;;; Sync

(defun account-group (acct designator)
  "Find a group by MLS id hex, Nostr group id hex, unique id prefix, or name."
  (let ((all (loop for g being the hash-values of (account-groups acct) collect g)))
    (or (gethash designator (account-groups acct))
        (find designator all :key (lambda (g) (octets->hex (mg-nostr-group-id g))) :test #'string=)
        (let ((by-prefix (remove-if-not (lambda (g) (and (<= (length designator) 64)
                                                         (string= designator (mg-id-hex g)
                                                                  :end2 (length designator))))
                                        all)))
          (and (= (length by-prefix) 1) (first by-prefix)))
        (find designator all :key #'mg-name :test #'string-equal))))

(defun %group-for-h (acct h)
  (loop for g being the hash-values of (account-groups acct)
        when (string= h (octets->hex (mg-nostr-group-id g))) return g))

(defun %record-message (acct mg plist)
  "Queue a delivered or sent message for the account's message log."
  (push (cons (mg-id-hex mg) plist) (account-unsaved-messages acct)))

(defparameter *refetch-overlap* 600
  "Seconds of overlap when resuming a chat's kind 445 fetch from its cursor:
relays and senders do not agree on clocks, and dedup absorbs the repeats.")

(defun %retry-deferred (acct mg)
  "Re-process deferred events; those that decrypt now leave the queue."
  (let ((waiting (reverse (marmot-group-deferred mg))) (results '()))
    (setf (marmot-group-deferred mg) '())
    (dolist (d waiting)
      (let ((r (process-group-event acct (cdr d))))
        (unless (equal r '((:type :undecryptable)))
          (setf results (append results r)))))
    results))

(defun prune-account (acct)
  "Bound the dedup tables: an event older than every chat's fetch window can
no longer be refetched; gift wraps are fetched from up to three days back."
  (let* ((now (unix-time))
         (cursors (loop for mg being the hash-values of (account-groups acct) collect (marmot-group-cursor mg)))
         (group-floor (- (if cursors (reduce #'min cursors) now) *refetch-overlap* 86400))
         (wrap-floor (- now (* 8 24 3600))))
    (loop for k being the hash-keys of (account-seen-group-events acct) using (hash-value at)
          when (or (not (integerp at)) (< at group-floor)) do (remhash k (account-seen-group-events acct)))
    (loop for k being the hash-keys of (account-seen-wraps acct) using (hash-value at)
          when (or (not (integerp at)) (< at wrap-floor)) do (remhash k (account-seen-wraps acct)))
    (loop for mg being the hash-values of (account-groups acct) do (prune-marmot-group mg))
    acct))

(defun process-group-event (acct ev)
  (when (gethash (ev:event-id ev) (account-seen-group-events acct))
    (return-from process-group-event nil))
  (let* ((h (ignore-errors (event-tag-value ev "h")))
         (mg (and h (%group-for-h acct h))))
    (when mg
      (let ((results (handler-case (receive-group-event mg ev)
                       (marmot-error (c) (list (list :type :rejected :reason (marmot-error-message c)))))))
        ;; undecryptable input may become readable after a later commit: it waits
        ;; in the chat's deferred queue, retried each sync (transports/nostr.md)
        (if (equal results '((:type :undecryptable)))
            (unless (find (ev:event-id ev) (marmot-group-deferred mg)
                          :key (lambda (d) (ev:event-id (cdr d))) :test #'string=)
              (push (cons (ev:event-created-at ev) ev) (marmot-group-deferred mg))
              (when (> (length (marmot-group-deferred mg)) 256)
                (setf (marmot-group-deferred mg) (subseq (marmot-group-deferred mg) 0 256))))
            (setf (gethash (ev:event-id ev) (account-seen-group-events acct)) (ev:event-created-at ev)))
        (dolist (r results)
          (case (getf r :type)
            (:own-commit-merged (queue-welcomes acct mg (getf r :staged)))
            (:message (%record-message acct mg r))
            (:message-invalidated (%record-message acct mg (list :type :invalidate :id (getf r :id))))))
        (when (account-on-event acct)
          (dolist (r results) (funcall (account-on-event acct) acct mg r)))
        results))))

(defun sync (acct)
  "Fetch and process new Welcomes and group traffic.  Returns the list of
results produced."
  (let ((results '())
        (since (max 0 (- (account-last-sync acct) (* 3 24 3600)))))  ; gift wraps are back-dated
    (setf (account-last-sync acct) (unix-time))
    (retry-pending-commits acct)
    (flush-outbox acct)
    (maintain-key-packages acct)
    (dolist (wrap (pool-query acct (account-relays acct)
                              (list (flt:make-filter :kinds '(1059) :tags (list (cons "p" (list (account-pubkey-hex acct))))
                                                     :since since))))
      (let ((mg (process-gift-wrap acct wrap)))
        (when mg (push (list :type :joined :group (mg-id-hex mg)) results))))
    ;; group traffic: what is new since each chat's cursor, oldest first
    (loop for mg being the hash-values of (account-groups acct)
          when (mls-group-active (marmot-group-mls mg))
            do (let* ((gid (octets->hex (mg-nostr-group-id mg)))
                      (events (sort (pool-query acct (mg-relays mg)
                                                (list (flt:make-filter
                                                       :kinds '(445) :tags (list (cons "h" (list gid)))
                                                       :since (max 0 (- (marmot-group-cursor mg) *refetch-overlap*)))))
                                    #'< :key #'ev:event-created-at)))
                 (dolist (ev events)
                   (let ((r (process-group-event acct ev)))
                     (when r (setf results (append results (remove :undecryptable r :key (lambda (x) (getf x :type))))))))
                 (when events
                   (setf (marmot-group-cursor mg)
                         (min (unix-time) (max (marmot-group-cursor mg)
                                               (reduce #'max events :key #'ev:event-created-at)))))))
    ;; a commit can make deferred events decryptable: retry while that makes progress
    (loop repeat 8
          do (let ((before (loop for mg being the hash-values of (account-groups acct)
                                 sum (length (marmot-group-deferred mg)))))
               (loop for mg being the hash-values of (account-groups acct)
                     do (setf results (append results (%retry-deferred acct mg))))
               (when (= before (loop for mg being the hash-values of (account-groups acct)
                                     sum (length (marmot-group-deferred mg))))
                 (return))))
    (commit-pending-self-removes acct)
    (prune-account acct)
    results))

;;; ---------------------------------------------------------------------------
;;; Outbound

;;; Welcome delivery is an outbox: each invitee's Welcome is recorded (and
;;; saved) when its commit becomes canonical, then delivered and retried
;;; independently until a relay in the invitee's inbox set accepts it.

(defun queue-welcomes (acct mg staged)
  (when (and staged (staged-commit-welcome staged) (staged-commit-invitees staged))
    (loop for (pk . kp-event-id) in (staged-commit-invitees staged)
          do (push (list :group (mg-id-hex mg) :pubkey pk :kp-event-id kp-event-id
                         :welcome (octets->hex (staged-commit-welcome staged))
                         :relays (mg-relays mg) :attempts 0)
                   (account-outbox acct)))
    (%checkpoint acct)
    (flush-outbox acct)))

(defun flush-outbox (acct)
  "Try every owed Welcome once.  Returns the list of (pubkey delivered-p)."
  (let ((results '()))
    (dolist (entry (reverse (account-outbox acct)))
      (let* ((pk (getf entry :pubkey))
             (ok (handler-case
                     (let* ((inbox (or (fetch-relay-list acct pk 10050) (account-relays acct)))
                            (rumor (welcome-rumor (account-pubkey acct) (hex->octets (getf entry :welcome))
                                                  (getf entry :kp-event-id) (getf entry :relays))))
                       (publish-accepted-p (%publish acct inbox (gift-wrap rumor (account-sk acct) pk) :require nil)))
                   (error () nil))))
        (if ok
            (setf (account-outbox acct) (remove entry (account-outbox acct)))
            (incf (getf entry :attempts)))
        (push (list pk ok) results)))
    (nreverse results)))

(defun %invitees (acct invitee-pubkeys)
  "Resolve and fetch a KeyPackage for each invitee: list of (pubkey-hex . kp-event)."
  (mapcar (lambda (pk)
            (let ((hex (octets->hex (parse-pubkey pk))))
              (cons hex (nth-value 1 (fetch-key-package acct hex)))))
          invitee-pubkeys))

(defun %stage-adds (mg invitees)
  (let ((staged (stage-commit mg :proposals (add-proposals-for
                                             (mapcar (lambda (i) (validate-key-package-event (cdr i)))
                                                     invitees)))))
    (setf (staged-commit-invitees staged)
          (mapcar (lambda (i) (cons (car i) (ev:event-id (cdr i)))) invitees))
    staged))

(defun create-group-with (acct name invitee-pubkeys &key (description "") relays)
  "Founding creation (publish-lifecycle.md 'Group creation'): epoch 0, then a
locally merged founding Add commit, then one Welcome per invitee."
  (let* ((invitees (%invitees acct invitee-pubkeys))
         (mg (create-marmot-group (account-sk acct) :name name :description description
                                                     :relays (or relays (account-relays acct)))))
    (setf (gethash (mg-id-hex mg) (account-groups acct)) mg)
    (when invitees
      (let ((staged (%stage-adds mg invitees)))
        (merge-pending mg)              ; founding: an empty publish obligation
        (queue-welcomes acct mg staged)))
    (%checkpoint acct)
    mg))

(defun %publish-pending (acct mg)
  "One attempt at the pending commit's publish obligation.  Returns the relay
results; on an acknowledgement the commit is merged and its Welcomes queued."
  (let* ((staged (marmot-group-pending mg))
         (ev (seal-group-message (marmot-group-mls mg) (staged-commit-message staged)))
         (results (%publish acct (mg-relays mg) ev :require nil)))
    (setf (gethash (ev:event-id ev) (account-seen-group-events acct)) (ev:event-created-at ev))
    (when (publish-accepted-p results)
      (merge-pending mg)
      (%checkpoint acct)
      (queue-welcomes acct mg staged))
    results))

(defun publish-commit (acct mg)
  "Publish the pending commit to the group's (pre-commit) relays.  It is saved
first; if no relay acknowledges it, it stays pending (the bytes may already be
out) and every sync republishes the same MLS bytes until it is acknowledged,
echoed back, or superseded by another member's commit."
  (%checkpoint acct)
  (let ((results (%publish-pending acct mg)))
    (unless (publish-accepted-p results)
      (marmot-fail "no relay acknowledged the commit (~{~A~^; ~}); it is saved and will be republished on the next sync"
                   (mapcar (lambda (r) (format nil "~A: ~A" (first r) (or (third r) "no reply"))) results)))
    results))

(defun retry-pending-commits (acct)
  (loop for mg being the hash-values of (account-groups acct)
        for staged = (marmot-group-pending mg)
        when staged
          do (if (= (mls-group-epoch (staged-commit-new-group staged)) (1+ (mg-epoch mg)))
                 (handler-case (%publish-pending acct mg) (error () nil))
                 (discard-pending mg))))

(defun invite (acct mg invitee-pubkeys)
  (unless (active-admin-p (marmot-group-mls mg) (account-pubkey acct))
    (marmot-fail "only an active admin may invite"))
  (%stage-adds mg (%invitees acct invitee-pubkeys))
  (publish-commit acct mg))

(defun remove-members (acct mg pubkeys)
  (let* ((mls (marmot-group-mls mg))
         (targets (mapcar (lambda (pk) (parse-pubkey pk)) pubkeys))
         (leaves (loop for (i . ln) in (mls-group-members mls)
                       when (member (leaf-account ln) targets :test #'octets=) collect i))
         (admins (remove-if (lambda (a) (member a targets :test #'octets=)) (group-admins mls)))
         (proposals (mapcar (lambda (i) (make-proposal :type +prop-remove+ :removed i)) leaves)))
    (unless (active-admin-p mls (account-pubkey acct)) (marmot-fail "only an active admin may remove members"))
    (unless leaves (marmot-fail "none of those accounts is a member"))
    (unless (equalp admins (group-admins mls))
      (push (make-proposal :type +prop-app-data-update+ :component-id +c-admin-policy+
                           :operation 1 :data (encode-admin-policy admins))
            proposals))
    (stage-commit mg :proposals proposals)
    (publish-commit acct mg)))

(defun rename-group (acct mg name &optional (description (or (nth-value 1 (group-profile (marmot-group-mls mg))) "")))
  (unless (active-admin-p (marmot-group-mls mg) (account-pubkey acct)) (marmot-fail "only an active admin may rename"))
  (stage-commit mg :proposals (list (make-proposal :type +prop-app-data-update+ :component-id +c-profile+
                                                   :operation 1 :data (encode-group-profile name description))))
  (publish-commit acct mg))

(defun self-update (acct mg)
  (stage-commit mg)
  (publish-commit acct mg))

(defun send-message (acct mg text &key (kind 9) (tags '()))
  (let ((ev (send-app-message mg (account-pubkey acct) kind text :tags tags)))
    (%record-message acct mg (first (marmot-group-messages mg)))
    (setf (gethash (ev:event-id ev) (account-seen-group-events acct)) (ev:event-created-at ev))
    (%publish acct (mg-relays mg) ev)))

;;; ---------------------------------------------------------------------------
;;; Admin policy and departure

(defun set-admins (acct mg admins)
  "Commit a full admin-policy replacement (promote / demote)."
  (stage-commit mg :proposals (list (make-proposal :type +prop-app-data-update+ :component-id +c-admin-policy+
                                                   :operation 1 :data (encode-admin-policy admins))))
  (publish-commit acct mg))

(defun promote (acct mg pubkey)
  (let ((pk (parse-pubkey pubkey)) (mls (marmot-group-mls mg)))
    (unless (member pk (group-member-accounts mls) :test #'octets=) (marmot-fail "not a member"))
    (set-admins acct mg (cons pk (group-admins mls)))))

(defun demote (acct mg pubkey)
  (let* ((pk (parse-pubkey pubkey))
         (rest (remove pk (group-admins (marmot-group-mls mg)) :test #'octets=)))
    (unless rest (marmot-fail "the group must keep at least one admin"))
    (set-admins acct mg rest)))

(defun leave-group (acct mg)
  "member-departure.md: an admin first leaves the admin list (needs another
admin), then publishes a SelfRemove proposal for a remaining member to commit."
  (let ((mls (marmot-group-mls mg)))
    (when (active-admin-p mls (account-pubkey acct))
      (let ((others (remove (account-pubkey acct) (group-admins mls) :test #'octets=)))
        (unless others (marmot-fail "you are the only admin: promote someone first"))
        (set-admins acct mg others)))
    (let ((ev (self-remove-message mg)))
      (setf (gethash (ev:event-id ev) (account-seen-group-events acct)) (ev:event-created-at ev))
      (%publish acct (mg-relays mg) ev)
      (setf (marmot-group-leaving mg) t))))

(defun commit-pending-self-removes (acct)
  "Commit retained peer SelfRemove proposals (one SelfRemove-only commit per
group).  Returns the groups advanced."
  (loop for mg being the hash-values of (account-groups acct)
        for removes = (and (mls-group-active (marmot-group-mls mg))
                           (not (marmot-group-leaving mg))
                           (pending-self-removes mg))
        when removes
          collect (handler-case (progn (stage-commit mg :by-reference removes)
                                       (publish-commit acct mg)
                                       mg)
                    (error (c) (discard-pending mg) (warn "SelfRemove commit: ~A" c) nil))))
