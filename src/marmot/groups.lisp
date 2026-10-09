;;;; groups.lisp — Marmot groups over the Nostr transport
;;;;
;;;; A MARMOT-GROUP wraps the canonical MLS-GROUP plus what Marmot reads out of
;;;; its GroupContext (admins, routing, profile) and the small amount of
;;;; transport state needed to receive: retained prior epochs (for trial
;;;; decryption of late kind 445 envelopes) and the set of MLS message ids
;;;; already processed (dedup across relays).
;;;;
;;;; Convergence (protocol-core/convergence.md) is implemented in its simplest
;;;; linear form: the first valid commit for the current epoch wins and the
;;;; prior epoch is retained.  Same-epoch races are reported, not resolved.

(in-package #:cl-marmot)

(defparameter *retained-epochs* 4
  "How many prior epochs to keep for decrypting late application messages.")

(defstruct marmot-group
  mls                     ; canonical MLS-GROUP
  (retained '())          ; prior MLS-GROUPs, newest first
  (seen (make-hash-table :test #'equal))   ; message-id hex -> T
  pending                 ; STAGED-COMMIT awaiting publication
  (messages '())          ; delivered app events, newest first (plist per message)
  (log '())               ; state notifications, newest first
  (leaving nil))          ; T after we published a SelfRemove (member-departure.md)

(defun mg-id (mg) (mls-group-id (marmot-group-mls mg)))
(defun mg-id-hex (mg) (octets->hex (mg-id mg)))
(defun mg-epoch (mg) (mls-group-epoch (marmot-group-mls mg)))

(defun %gc-dict (mls) (or (extensions-app-data (mls-group-extensions mls)) '()))

(defun group-admins (mls)
  (let ((d (app-data-get (%gc-dict mls) +c-admin-policy+)))
    (and d (decode-admin-policy d))))

(defun group-routing (mls)
  "Returns (values nostr-group-id relays) or NIL."
  (let ((d (app-data-get (%gc-dict mls) +c-nostr-routing+)))
    (and d (decode-nostr-routing d))))

(defun group-profile (mls)
  "Returns (values name description) or NIL."
  (let ((d (app-data-get (%gc-dict mls) +c-profile+)))
    (and d (decode-group-profile d))))

(defun group-retention-secs (mls)
  "Disappearing-message duration in seconds (0 = disabled or absent)."
  (let ((d (app-data-get (%gc-dict mls) +c-message-retention+)))
    (if d (decode-message-retention d) 0)))

(defun group-required-components (mls)
  (let ((d (app-data-get (%gc-dict mls) +component-app-components+)))
    (and d (decode-component-id-list d))))

(defun mg-nostr-group-id (mg) (nth-value 0 (group-routing (marmot-group-mls mg))))
(defun mg-relays (mg) (nth-value 1 (group-routing (marmot-group-mls mg))))
(defun mg-name (mg) (or (group-profile (marmot-group-mls mg)) ""))

(defun group-member-accounts (mls)
  (remove-duplicates (mapcar (lambda (m) (leaf-account (cdr m))) (mls-group-members mls)) :test #'octets=))

(defun active-admin-p (mls account)
  (and (member account (group-admins mls) :test #'octets=)
       (member account (group-member-accounts mls) :test #'octets=)
       t))

;;; ---------------------------------------------------------------------------
;;; Validation of a resulting epoch (group-setup.md invariants)

(defun validate-marmot-group-state (mls)
  (let ((required (group-required-components mls))
        (rc (extensions-required-capabilities (mls-group-extensions mls))))
    (unless (member +c-identity-proof+ required) (marmot-fail "group does not require 0x8009"))
    (unless (member +c-admin-policy+ required) (marmot-fail "group does not require 0x8003"))
    (unless rc (marmot-fail "group has no required_capabilities"))
    (unless (member +prop-app-data-update+ (required-capabilities-proposal-types rc))
      (marmot-fail "group does not require app_data_update"))
    (let ((admins (group-admins mls)))
      (unless admins (marmot-fail "group has no admin policy"))
      (let ((accounts (group-member-accounts mls)))
        (dolist (a admins)
          (unless (member a accounts :test #'octets=)
            (marmot-fail "admin ~A has no member leaf" (octets->hex a))))))
    (when (member +c-lifecycle+ required)
      (let ((d (app-data-get (%gc-dict mls) +c-lifecycle+)))
        (unless d (marmot-fail "lifecycle required but absent"))
        (decode-lifecycle d)))
    (dolist (m (mls-group-members mls))
      (validate-marmot-leaf (cdr m))
      ;; every member supports every required component
      (let ((supported (leaf-supported-components (cdr m))))
        (dolist (c required)
          (unless (or (< c #x8000) (member c supported))
            (marmot-fail "member ~D does not support required component 0x~4,'0X" (car m) c)))))
    (multiple-value-bind (gid relays) (group-routing mls)
      (declare (ignore gid))
      (unless relays (marmot-fail "group has no Nostr routing")))
    t))

;;; ---------------------------------------------------------------------------
;;; Outer kind 445 envelope (transports/nostr.md "Group message delivery")

(defun group-event-key (mls)
  (mls-group-export mls "marmot" "group-event" 32))

(defun seal-group-message (mls mls-message-octets &key expiration)
  "A kind 445 event carrying MLS-MESSAGE-OCTETS for group MLS, signed by a
fresh ephemeral key."
  (let* ((nonce (random-octets 12))
         (ct (chacha20-poly1305-encrypt (group-event-key mls) nonce mls-message-octets (make-octets 0)))
         (gid (group-routing mls)))
    (make-signed-event (generate-nostr-key)
                       :kind 445
                       :content (octets->base64 (concat-octets nonce ct))
                       :tags (append (list (list "h" (octets->hex gid)))
                                     (and expiration (list (list "expiration" (format nil "~D" expiration))))))))

(defun %validate-445-shape (ev)
  (unless (= (nostr-event-kind ev) 445) (marmot-fail "not kind 445"))
  (dolist (tag (nostr-event-tags ev))
    (unless (member (first tag) '("h" "expiration") :test #'string=)
      (marmot-fail "kind 445 carries a forbidden tag ~S" (first tag))))
  (let ((h (event-tag-value ev "h")))
    (unless (%lower-hex-p h 64) (marmot-fail "bad h tag"))
    h))

(defun open-group-message (mls ev)
  "Try to decrypt kind 445 EV under MLS's epoch key.  Returns the MLS message
octets or NIL if this epoch's key does not authenticate it."
  (let ((data (handler-case (base64->octets (nostr-event-content ev)) (base64-error () nil))))
    (when (and data (>= (length data) 28))
      (handler-case (chacha20-poly1305-decrypt (group-event-key mls) (subseq-octets data 0 12)
                                               (subseq-octets data 12) (make-octets 0))
        (aead-error () nil)))))

;;; ---------------------------------------------------------------------------
;;; App payloads (foundation/application-messages.md)

(defun make-app-event (account-pubkey kind content &key (tags '()) (created-at (unix-time)))
  (make-unsigned-event :pubkey account-pubkey :kind kind :tags tags :content content
                       :created-at created-at))

(defun encode-app-event (ev) (string->utf8 (event->json ev)))

(defun decode-app-event (octets)
  "Strict decode: exactly the six members, no sig, no duplicate keys, id
matches."
  (let* ((obj (parse-json (utf8->string octets) :reject-duplicate-keys t)))
    (unless (= (length (cdr obj)) 6) (marmot-fail "app event must have exactly six members"))
    (let ((ev (jobj->event obj :allow-sig nil :strict t)))
      (unless (string= (nostr-event-id ev) (compute-event-id ev)) (marmot-fail "app event id mismatch"))
      ev)))

;;; ---------------------------------------------------------------------------
;;; Authorization (group-messaging.md "Commit authorization", admin-policy-v1.md)

(defun %leaf-account-at (mls leaf-index)
  (let ((ln (mls-group-member-leaf mls leaf-index)))
    (and ln (leaf-account ln))))

(defun proposal-authorization-error (mls proposal sender)
  "NIL if SENDER may send PROPOSAL as a standalone proposal in state MLS."
  (let ((admin (active-admin-p mls (%leaf-account-at mls sender)))
        (ty (proposal-type proposal)))
    (cond ((= ty +prop-self-remove+)
           (and admin "an active admin may not SelfRemove"))
          (admin nil)
          (t (format nil "non-admin standalone proposal of type ~D" ty)))))

(defun commit-authorization-error (mls committer proposals)
  "NIL if COMMITTER may commit PROPOSALS ((proposal . sender) pairs) against
candidate parent MLS."
  (let ((admin (active-admin-p mls (%leaf-account-at mls committer)))
        (types (mapcar (lambda (ps) (proposal-type (car ps))) proposals)))
    ;; every SelfRemove must target its (non-admin) sender
    (dolist (ps proposals)
      (when (= (proposal-type (car ps)) +prop-self-remove+)
        (when (active-admin-p mls (%leaf-account-at mls (cdr ps)))
          (return-from commit-authorization-error "SelfRemove from an active admin"))
        (when (eql (cdr ps) committer)
          (return-from commit-authorization-error "committer commits its own SelfRemove"))))
    (cond (admin nil)
          ((null proposals) nil)                                  ; self-update
          ((every (lambda (ty) (= ty +prop-self-remove+)) types) nil) ; SelfRemove-only
          (t (format nil "non-admin commit with proposal types ~S" types)))))

;;; ---------------------------------------------------------------------------
;;; Receiving

(defun %retain (mg old)
  (push old (marmot-group-retained mg))
  (when (> (length (marmot-group-retained mg)) *retained-epochs*)
    (setf (marmot-group-retained mg) (subseq (marmot-group-retained mg) 0 *retained-epochs*))))

(defun %note (mg &rest plist)
  (push plist (marmot-group-log mg))
  plist)

(defun %apply-new-epoch (mg new &key commit committer)
  "Make NEW canonical after Marmot validation; returns notifications."
  (let ((old (marmot-group-mls mg)))
    (if (mls-group-active new)
        (validate-marmot-group-state new)
        (progn (%retain mg old)
               (setf (marmot-group-mls mg) new)
               (return-from %apply-new-epoch
                 (list (%note mg :type :removed :epoch (mls-group-epoch old))))))
    (let ((before (group-member-accounts old))
          (after (group-member-accounts new))
          (notes '()))
      (%retain mg old)
      (setf (marmot-group-mls mg) new)
      (dolist (a after)
        (unless (member a before :test #'octets=)
          (push (%note mg :type :member-added :account a :epoch (mls-group-epoch new)) notes)))
      (dolist (a before)
        (unless (member a after :test #'octets=)
          (push (%note mg :type :member-removed :account a :epoch (mls-group-epoch new)) notes)))
      (unless (equalp (multiple-value-list (group-profile old)) (multiple-value-list (group-profile new)))
        (push (%note mg :type :renamed :name (group-profile new)) notes))
      (push (%note mg :type :epoch :epoch (mls-group-epoch new) :committer committer
                      :commit (and commit t))
            notes)
      (nreverse notes))))

(defun receive-group-event (mg ev)
  "Process a verified kind 445 event.  Returns a list of results (plists):
(:type :message ...), state notifications, (:type :duplicate) or
(:type :undecryptable)."
  (%validate-445-shape ev)
  (let* ((candidates (cons (marmot-group-mls mg) (marmot-group-retained mg)))
         (state nil)
         (bytes (loop for c in candidates
                      for b = (open-group-message c ev)
                      when b do (setf state c) (return b))))
    (unless bytes (return-from receive-group-event (list (list :type :undecryptable))))
    (let ((mid (octets->hex (sha256 bytes))))
      (when (gethash mid (marmot-group-seen mg)) (return-from receive-group-event (list (list :type :duplicate))))
      (setf (gethash mid (marmot-group-seen mg)) t)
      (let ((msg (tls-deserialize 'mls-message bytes)))
        (cond
          ;; our own pending commit coming back
          ((and (marmot-group-pending mg)
                (octets= bytes (staged-commit-message (marmot-group-pending mg))))
           (list (list :type :own-commit-echo)))
          ((/= (mls-message-wire-format msg) +wf-private-message+)
           ;; handshake: only against the canonical state
           (unless (eq state (marmot-group-mls mg))
             (return-from receive-group-event (list (list :type :stale))))
           (let ((r (handler-case (process-message state bytes)
                      (mls-error (c) (return-from receive-group-event
                                       (list (list :type :rejected :reason (mls-error-message c))))))))
             (ecase (getf r :type)
               (:proposal
                (let ((why (proposal-authorization-error state (getf r :proposal) (getf r :sender))))
                  (if why
                      (progn (setf (mls-group-proposals state)
                                   (remove (getf r :ref) (mls-group-proposals state)
                                           :key (lambda (x) (getf x :ref)) :test #'octets=))
                             (list (list :type :rejected :reason why)))
                      (list (list :type :proposal :sender (getf r :sender)
                                  :proposal-type (proposal-type (getf r :proposal)))))))
               (:commit
                (let ((why (commit-authorization-error
                            state (getf r :sender)
                            (%resolve-proposals state (getf r :commit) (getf r :sender)))))
                  (if why
                      (list (list :type :rejected :reason why))
                      (handler-case (%apply-new-epoch mg (getf r :new-group)
                                                      :commit (getf r :commit)
                                                      :committer (getf r :sender))
                        (marmot-error (c)
                          (list (list :type :rejected :reason (marmot-error-message c)))))))))))
          (t
           (let ((r (handler-case (process-message state bytes)
                      (mls-error (c) (return-from receive-group-event
                                       (list (list :type :rejected :reason (mls-error-message c))))))))
             (case (getf r :type)
               (:application
                (let* ((leaf (getf r :sender-leaf))
                       (app (handler-case (decode-app-event (getf r :data))
                              (error (c) (return-from receive-group-event
                                           (list (list :type :rejected :reason (format nil "app payload: ~A" c))))))))
                  (if (string= (nostr-event-pubkey app) (octets->hex (leaf-account leaf)))
                      (let ((m (list :type :message :epoch (mls-group-epoch state)
                                     :sender (nostr-event-pubkey app)
                                     :kind (nostr-event-kind app) :content (nostr-event-content app)
                                     :tags (nostr-event-tags app) :id (nostr-event-id app)
                                     :created-at (nostr-event-created-at app))))
                        (push m (marmot-group-messages mg))
                        (list m))
                      (list (list :type :rejected :reason "app event pubkey is not the MLS sender")))))
               (:proposal (list (list :type :proposal :sender (getf r :sender))))
               (:commit (handler-case (%apply-new-epoch mg (getf r :new-group) :committer (getf r :sender))
                          (marmot-error (c) (list (list :type :rejected :reason (marmot-error-message c))))))))))))))

;;; ---------------------------------------------------------------------------
;;; Joining (protocol-core/joining.md)

(defun welcome-rumor-parts (rumor)
  "Validate a kind 444 rumor.  Returns (values welcome-struct kp-event-id relays)."
  (unless (= (nostr-event-kind rumor) 444) (marmot-fail "not a welcome rumor"))
  (let ((e (event-tag-value rumor "e"))
        (relays (event-tag-values rumor "relays")))
    (unless (%lower-hex-p e 64) (marmot-fail "bad e tag"))
    (unless relays (marmot-fail "empty relays tag"))
    (let ((msg (handler-case (tls-deserialize 'mls-message (base64->octets (nostr-event-content rumor)))
                 (error (c) (marmot-fail "welcome content: ~A" c)))))
      (unless (= (mls-message-wire-format msg) +wf-welcome+) (marmot-fail "content is not mls_welcome"))
      (values (mls-message-body msg) e relays))))

(defun join-marmot-group (welcome bundle)
  "Steps 4-8 of the receiving flow.  Returns a MARMOT-GROUP; signals on any
failure without touching BUNDLE."
  (multiple-value-bind (mls gi)
      (handler-case (join-from-welcome welcome bundle)
        (mls-error (c) (marmot-fail "Welcome: ~A" (mls-error-message c))))
    (unless (find-extension (group-info-extensions gi) +ext-ratchet-tree+)
      (marmot-fail "GroupInfo carries no ratchet tree"))
    (validate-marmot-group-state mls)
    (let ((author (mls-group-member-leaf mls (group-info-signer gi))))
      (unless (active-admin-p mls (leaf-account author))
        (marmot-fail "Welcome author is not an active admin")))
    (make-marmot-group :mls mls)))

;;; ---------------------------------------------------------------------------
;;; Creating groups and committing (publish-before-apply)

(defun marmot-group-context-extensions (&key creator-account admins nostr-group-id relays name description)
  (list
   (make-extension :type +ext-required-capabilities+
                   :data (tls-serialize 'required-capabilities
                                        (make-required-capabilities
                                         :extension-types (list +ext-app-data-dictionary+)
                                         :proposal-types (list +prop-app-data-update+)
                                         :credential-types '())))
   (app-data-extension
    (remove nil
            (list (make-component-data :component-id +component-app-components+
                                       :data (encode-component-id-list
                                              (list +c-admin-policy+ +c-nostr-routing+
                                                    +c-identity-proof+ +c-lifecycle+)))
                  (and name (make-component-data :component-id +c-profile+
                                                 :data (encode-group-profile name (or description ""))))
                  (make-component-data :component-id +c-admin-policy+
                                       :data (encode-admin-policy (or admins (list creator-account))))
                  (make-component-data :component-id +c-nostr-routing+
                                       :data (encode-nostr-routing nostr-group-id relays))
                  (make-component-data :component-id +c-lifecycle+ :data (encode-lifecycle :active)))))))

(defun create-marmot-group (account-sk &key name (description "") relays (admins nil))
  "Epoch 0 of a new group whose only member is us.  Returns a MARMOT-GROUP."
  (let* ((me (secp256k1-xonly-pubkey account-sk))
         (bundle (make-marmot-key-package account-sk :last-resort nil))
         (leaf (key-package-leaf-node (key-package-bundle-key-package bundle)))
         (mls (create-group :group-id (random-octets 32)
                            :leaf-node leaf
                            :sig-sk (key-package-bundle-sig-sk bundle)
                            :leaf-sk (key-package-bundle-leaf-sk bundle)
                            :extensions (marmot-group-context-extensions
                                         :creator-account me :admins (cons me admins)
                                         :nostr-group-id (random-octets 32)
                                         :relays relays :name name :description description))))
    (validate-marmot-group-state mls)
    (make-marmot-group :mls mls)))

(defun stage-commit (mg &rest args)
  "Prepare a commit (see CREATE-COMMIT).  Records it as pending and returns
the STAGED-COMMIT.  Marmot authorization is checked against the current state."
  (when (marmot-group-pending mg) (marmot-fail "a commit is already pending"))
  (when (marmot-group-leaving mg) (marmot-fail "we are leaving this group"))
  (let* ((mls (marmot-group-mls mg))
         (own (mls-group-own-leaf mls))
         (why (commit-authorization-error
               mls own (append (mapcar (lambda (p) (cons p own)) (getf args :proposals))
                               (mapcar (lambda (rp) (cons (getf rp :proposal) (getf rp :sender)))
                                       (getf args :by-reference))))))
    (when why (marmot-fail "not authorized: ~A" why)))
  (let ((staged (handler-case (apply #'create-commit (marmot-group-mls mg) args)
                  (mls-error (c) (marmot-fail "~A" (mls-error-message c))))))
    (validate-marmot-group-state (staged-commit-new-group staged))
    (setf (marmot-group-pending mg) staged)))

(defun merge-pending (mg)
  "Publication succeeded: the staged commit becomes canonical."
  (let ((staged (marmot-group-pending mg)))
    (unless staged (marmot-fail "nothing pending"))
    (setf (gethash (octets->hex (sha256 (staged-commit-message staged))) (marmot-group-seen mg)) t)
    (setf (marmot-group-pending mg) nil)
    (%apply-new-epoch mg (staged-commit-new-group staged) :committer (mls-group-own-leaf (marmot-group-mls mg)))))

(defun discard-pending (mg) (setf (marmot-group-pending mg) nil))

(defun add-proposals-for (key-packages)
  (mapcar (lambda (kp) (make-proposal :type +prop-add+ :key-package kp)) key-packages))

(defun welcome-rumor (account-pubkey staged kp-event-id relays)
  (make-unsigned-event :pubkey account-pubkey :kind 444
                       :tags (list (list "e" kp-event-id) (cons "relays" relays))
                       :content (octets->base64 (staged-commit-welcome staged))))

(defun pending-self-removes (mg)
  "Retained SelfRemove proposals from other members (plists), at most one per
leaving leaf: the one with the lowest proposal digest."
  (let* ((mls (marmot-group-mls mg))
         (own (mls-group-own-leaf mls))
         (best (make-hash-table)))
    (dolist (rp (mls-group-proposals mls))
      (when (and (= (proposal-type (getf rp :proposal)) +prop-self-remove+)
                 (/= (getf rp :sender) own)
                 (mls-group-member-leaf mls (getf rp :sender)))
        (let ((cur (gethash (getf rp :sender) best)))
          (when (or (null cur) (octets< (getf rp :digest) (getf cur :digest)))
            (setf (gethash (getf rp :sender) best) rp)))))
    (loop for v being the hash-values of best collect v)))

(defun self-remove-message (mg)
  "Our SelfRemove proposal as a kind 445 event (member-departure.md)."
  (let ((mls (marmot-group-mls mg)))
    (when (active-admin-p mls (%leaf-account-at mls (mls-group-own-leaf mls)))
      (marmot-fail "an admin must leave the admin list before leaving"))
    (multiple-value-bind (bytes ref) (create-proposal-message mls (make-proposal :type +prop-self-remove+))
      (declare (ignore ref))
      (setf (gethash (octets->hex (sha256 bytes)) (marmot-group-seen mg)) t)
      (seal-group-message mls bytes))))

(defun send-app-message (mg account-pubkey kind content &key (tags '()))
  "Encrypt an app event; returns the kind 445 event to publish."
  (when (marmot-group-leaving mg) (marmot-fail "we are leaving this group"))
  (let* ((mls (marmot-group-mls mg))
         (app (make-app-event account-pubkey kind content :tags tags))
         (bytes (create-application-message mls (encode-app-event app)))
         (secs (group-retention-secs mls))
         ;; message-retention-v1: exact u64 created_at + duration, else no tag
         (expiry (and (plusp secs)
                      (let ((e (+ (nostr-event-created-at app) secs)))
                        (and (< e (expt 2 64)) e)))))
    (setf (gethash (octets->hex (sha256 bytes)) (marmot-group-seen mg)) t)
    (push (list :type :message :epoch (mls-group-epoch mls) :sender (nostr-event-pubkey app)
                :kind kind :content content :tags tags :id (nostr-event-id app)
                :created-at (nostr-event-created-at app) :own t)
          (marmot-group-messages mg))
    (seal-group-message mls bytes :expiration expiry)))
