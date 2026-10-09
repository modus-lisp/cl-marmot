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
  (pool (make-pool))
  (key-packages '())                   ; list of plists (:bundle :event-id :ref :d)
  (groups (make-hash-table :test #'equal))   ; MLS group id hex -> MARMOT-GROUP
  (seen-wraps (make-hash-table :test #'equal))
  (seen-group-events (make-hash-table :test #'equal))
  (last-sync 0)
  (on-event nil))                      ; (lambda (account group result)) for UIs

(defun account-pubkey-hex (acct) (octets->hex (account-pubkey acct)))
(defun account-npub (acct) (npub-encode (account-pubkey acct)))

(defun make-account-from-secret (sk &key relays)
  (make-account :sk sk :pubkey (secp256k1-xonly-pubkey sk) :relays relays))

(defun new-account (&key relays)
  (make-account-from-secret (generate-nostr-key) :relays relays))

(defun %publish (acct urls ev &key (require t))
  (let ((results (pool-publish (account-pool acct) urls ev)))
    (when (and require (not (publish-accepted-p results)))
      (marmot-fail "no relay accepted kind ~D: ~S" (nostr-event-kind ev) results))
    results))

;;; ---------------------------------------------------------------------------
;;; Account preparation (transports/nostr.md "Migration from kind 10051")

(defun publish-relay-lists (acct)
  (%publish acct (account-relays acct) (relay-list-event (account-sk acct) 10002 (account-relays acct)))
  (%publish acct (account-relays acct) (relay-list-event (account-sk acct) 10050 (account-relays acct))))

(defun publish-profile (acct name)
  (%publish acct (account-relays acct)
            (make-signed-event (account-sk acct) :kind 0 :content (to-json (jobj "name" name "display_name" name)))))

(defun publish-key-package (acct &key (d (random-octets 32)))
  "Create and publish a fresh KeyPackage in slot D.  Returns its plist."
  (let* ((bundle (make-marmot-key-package (account-sk acct)))
         (ev (key-package-event (account-sk acct) bundle d))
         (entry (list :bundle bundle :event-id (nostr-event-id ev)
                      :ref (octets->hex (key-package-ref (key-package-bundle-key-package bundle)))
                      :d d)))
    (%publish acct (account-relays acct) ev)
    (push entry (account-key-packages acct))
    entry))

(defun setup-account (acct &key name)
  (publish-relay-lists acct)
  (when name (publish-profile acct name))
  (publish-key-package acct))

;;; ---------------------------------------------------------------------------
;;; Directory lookups

(defun %latest (events)
  (first (sort (copy-list events) (lambda (a b)
                                    (or (> (nostr-event-created-at a) (nostr-event-created-at b))
                                        (and (= (nostr-event-created-at a) (nostr-event-created-at b))
                                             (string< (nostr-event-id a) (nostr-event-id b))))))))

(defun fetch-relay-list (acct pubkey-hex kind &key (lookup-relays (account-relays acct)))
  (let ((ev (%latest (remove-if-not (lambda (e) (string= (nostr-event-pubkey e) pubkey-hex))
                                    (pool-query (account-pool acct) lookup-relays
                                                (list (filter "kinds" (list kind) "authors" (list pubkey-hex))))))))
    (and ev (if (= kind 10002) (nip65-write-relays ev) (nip17-inbox-relays ev)))))

(defun fetch-key-package (acct pubkey-hex)
  "Fetch, validate and choose one KeyPackage for PUBKEY-HEX.  Returns
(values key-package event)."
  (let* ((relays (or (fetch-relay-list acct pubkey-hex 10002)
                     (marmot-fail "~A has no NIP-65 relay list" pubkey-hex)))
         (events (pool-query (account-pool acct) relays
                             (list (filter "kinds" '(30443) "authors" (list pubkey-hex)))))
         (slots (make-hash-table :test #'equal)))
    ;; newest per (author, d) slot
    (dolist (ev events)
      (when (string= (nostr-event-pubkey ev) pubkey-hex)
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
                                         ((/= (nostr-event-created-at (cdr a)) (nostr-event-created-at (cdr b)))
                                          (> (nostr-event-created-at (cdr a)) (nostr-event-created-at (cdr b))))
                                         (t (octets< (key-package-ref (car a)) (key-package-ref (car b)))))))))))
        (values (car best) (cdr best))))))

;;; ---------------------------------------------------------------------------
;;; Welcomes

(defun process-gift-wrap (acct wrap)
  "Returns the new MARMOT-GROUP if WRAP was a Welcome we could join."
  (when (gethash (nostr-event-id wrap) (account-seen-wraps acct))
    (return-from process-gift-wrap nil))
  (setf (gethash (nostr-event-id wrap) (account-seen-wraps acct)) t)
  (let ((rumor (handler-case (gift-unwrap wrap (account-sk acct))
                 (error (c) (warn "gift wrap ~A: ~A" (nostr-event-id wrap) c) nil))))
    (when (and rumor (= (nostr-event-kind rumor) 444))
      (multiple-value-bind (welcome kp-event-id relays) (welcome-rumor-parts rumor)
        (declare (ignore relays))
        (let ((entry (find-if (lambda (e)
                                (find (hex->octets (getf e :ref)) (welcome-secrets welcome)
                                      :key #'encrypted-group-secrets-new-member :test #'octets=))
                              (account-key-packages acct))))
          (unless entry
            (warn "Welcome ~A references no KeyPackage of ours (e=~A)" (nostr-event-id rumor) kp-event-id)
            (return-from process-gift-wrap nil))
          (let ((mg (handler-case (join-marmot-group welcome (getf entry :bundle))
                      (marmot-error (c) (warn "rejected Welcome: ~A" (marmot-error-message c)) nil))))
            (when mg
              (when (gethash (mg-id-hex mg) (account-groups acct))
                (warn "Welcome for a group we already have; ignored")
                (return-from process-gift-wrap nil))
              (setf (gethash (mg-id-hex mg) (account-groups acct)) mg)
              (%note mg :type :joined :epoch (mg-epoch mg)
                        :inviter (nostr-event-pubkey rumor))
              ;; a last-resort KeyPackage stays usable; a single-use one is spent
              (unless (key-package-last-resort-p (key-package-bundle-key-package (getf entry :bundle)))
                (setf (account-key-packages acct) (remove entry (account-key-packages acct))))
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

(defun process-group-event (acct ev)
  (when (gethash (nostr-event-id ev) (account-seen-group-events acct))
    (return-from process-group-event nil))
  (let* ((h (ignore-errors (event-tag-value ev "h")))
         (mg (and h (%group-for-h acct h))))
    (when mg
      (let ((results (handler-case (receive-group-event mg ev)
                       (marmot-error (c) (list (list :type :rejected :reason (marmot-error-message c)))))))
        ;; undecryptable input may become readable after a later commit: keep it eligible
        (unless (equal results '((:type :undecryptable)))
          (setf (gethash (nostr-event-id ev) (account-seen-group-events acct)) t))
        (when (account-on-event acct)
          (dolist (r results) (funcall (account-on-event acct) acct mg r)))
        results))))

(defun sync (acct)
  "Fetch and process new Welcomes and group traffic.  Returns the list of
results produced."
  (let ((results '())
        (since (max 0 (- (account-last-sync acct) (* 3 24 3600)))))  ; gift wraps are back-dated
    (setf (account-last-sync acct) (unix-time))
    (dolist (wrap (pool-query (account-pool acct) (account-relays acct)
                              (list (filter "kinds" '(1059) "#p" (list (account-pubkey-hex acct))
                                            "since" since))))
      (let ((mg (process-gift-wrap acct wrap)))
        (when mg (push (list :type :joined :group (mg-id-hex mg)) results))))
    ;; group traffic, repeated while it makes progress (a commit can unlock queued messages)
    (loop repeat 8
          do (let ((progress nil))
               (loop for mg being the hash-values of (account-groups acct)
                     for gid = (octets->hex (mg-nostr-group-id mg))
                     do (let ((events (sort (pool-query (account-pool acct) (mg-relays mg)
                                                        (list (filter "kinds" '(445) "#h" (list gid))))
                                            #'< :key #'nostr-event-created-at)))
                          (dolist (ev events)
                            (let ((r (process-group-event acct ev)))
                              (when (and r (notany (lambda (x) (eq (getf x :type) :undecryptable)) r))
                                (setf progress t)
                                (setf results (append results r)))))))
               (unless progress (return))))
    (commit-pending-self-removes acct)
    results))

;;; ---------------------------------------------------------------------------
;;; Outbound

(defun %send-welcomes (acct mg staged invitees)
  "INVITEES: list of (pubkey-hex . kp-event).  Each Welcome is a separate
delivery to that invitee's inbox relays."
  (loop for (pk . kp-ev) in invitees
        collect (let* ((inbox (or (fetch-relay-list acct pk 10050) (account-relays acct)))
                       (rumor (welcome-rumor (account-pubkey acct) staged (nostr-event-id kp-ev) (mg-relays mg)))
                       (wrap (gift-wrap rumor (account-sk acct) pk)))
                  (list pk (publish-accepted-p (%publish acct inbox wrap :require nil))))))

(defun create-group-with (acct name invitee-pubkeys &key (description "") relays)
  "Founding creation (publish-lifecycle.md 'Group creation'): epoch 0, then a
locally merged founding Add commit, then one Welcome per invitee."
  (let* ((invitees (mapcar (lambda (pk)
                             (let ((hex (octets->hex (parse-pubkey pk))))
                               (cons hex (nth-value 1 (fetch-key-package acct hex)))))
                           invitee-pubkeys))
         (mg (create-marmot-group (account-sk acct) :name name :description description
                                                     :relays (or relays (account-relays acct)))))
    (setf (gethash (mg-id-hex mg) (account-groups acct)) mg)
    (when invitees
      (let ((staged (stage-commit mg :proposals (add-proposals-for
                                                 (mapcar (lambda (i) (validate-key-package-event (cdr i)))
                                                         invitees)))))
        (merge-pending mg)
        (%send-welcomes acct mg staged invitees)))
    mg))

(defun publish-commit (acct mg)
  "Publish the pending commit to the group's (pre-commit) relays; merge on
acknowledgement, discard otherwise.  Returns the relay results."
  (let* ((staged (marmot-group-pending mg))
         (ev (seal-group-message (marmot-group-mls mg) (staged-commit-message staged)))
         (results (%publish acct (mg-relays mg) ev :require nil)))
    (setf (gethash (nostr-event-id ev) (account-seen-group-events acct)) t)
    (if (publish-accepted-p results)
        (merge-pending mg)
        (progn (discard-pending mg) (marmot-fail "commit not accepted by any relay: ~S" results)))
    results))

(defun invite (acct mg invitee-pubkeys)
  (unless (active-admin-p (marmot-group-mls mg) (account-pubkey acct))
    (marmot-fail "only an active admin may invite"))
  (let* ((invitees (mapcar (lambda (pk)
                             (let ((hex (octets->hex (parse-pubkey pk))))
                               (cons hex (nth-value 1 (fetch-key-package acct hex)))))
                           invitee-pubkeys))
         (staged (stage-commit mg :proposals (add-proposals-for
                                              (mapcar (lambda (i) (validate-key-package-event (cdr i)))
                                                      invitees)))))
    (publish-commit acct mg)
    (%send-welcomes acct mg staged invitees)))

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
    (setf (gethash (nostr-event-id ev) (account-seen-group-events acct)) t)
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
      (setf (gethash (nostr-event-id ev) (account-seen-group-events acct)) t)
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
