;;;; group.lisp — MLS group state: creation, commits, Welcome, messages
;;;;
;;;; An MLS-GROUP value is one epoch of one member's view.  Operations that
;;;; change the epoch never mutate their input: CREATE-COMMIT returns the
;;;; staged next state alongside the bytes to publish (Marmot applies a local
;;;; commit only after it has been published), and PROCESS-COMMIT returns the
;;;; next state.  Within an epoch the secret tree is mutated in place (sending
;;;; or receiving consumes ratchet keys) — that is the point of it.

(in-package #:cl-marmot)

(defstruct mls-group
  context                 ; group-context
  tree                    ; ratchet-tree
  own-leaf                ; our leaf index
  sig-sk                  ; Ed25519 seed for our leaf
  node-sks                ; hash: node index -> HPKE private key (our leaf + direct path)
  secrets                 ; epoch-secrets
  secret-tree
  interim-hash
  confirmation-tag
  (proposals '())         ; received standalone proposals this epoch: list of plists
  (external-psks '())     ; alist: psk-id octets -> psk octets
  (resumption-psks '())   ; alist: epoch -> resumption psk (this group)
  (active t))             ; NIL once we have been removed

(defun mls-group-id (g) (group-context-group-id (mls-group-context g)))
(defun mls-group-epoch (g) (group-context-epoch (mls-group-context g)))
(defun mls-group-extensions (g) (group-context-extensions (mls-group-context g)))
(defun group-context-octets (gc) (tls-serialize 'group-context gc))

(defun mls-group-member-leaf (g leaf-index)
  (and (< leaf-index (rt-n-leaves (mls-group-tree g)))
       (rt-leaf (mls-group-tree g) leaf-index)))

(defun mls-group-own-leaf-node (g) (mls-group-member-leaf g (mls-group-own-leaf g)))

(defun mls-group-members (g)
  "List of (leaf-index . leaf-node) for every occupied leaf."
  (loop for i in (rt-leaf-indices (mls-group-tree g))
        collect (cons i (rt-leaf (mls-group-tree g) i))))

(defun mls-group-export (g label context length)
  (mls-exporter (epoch-secrets-exporter-secret (mls-group-secrets g)) label context length))

;;; ---------------------------------------------------------------------------
;;; Leaf nodes and KeyPackages

(defun sign-leaf-node (ln sig-sk &key group-id leaf-index)
  (setf (leaf-node-signature ln)
        (sign-with-label sig-sk "LeafNodeTBS" (leaf-node-tbs ln :group-id group-id :leaf-index leaf-index)))
  ln)

(defun verify-leaf-node-signature (ln &key group-id leaf-index)
  (verify-with-label (leaf-node-signature-key ln) "LeafNodeTBS"
                     (leaf-node-tbs ln :group-id group-id :leaf-index leaf-index)
                     (leaf-node-signature ln)))

(defstruct key-package-bundle
  key-package             ; the public KeyPackage
  init-sk                 ; HPKE private key for init_key
  leaf-sk                 ; HPKE private key for the leaf encryption_key
  sig-sk)                 ; Ed25519 seed for the leaf signature_key

(defun make-key-package-bundle* (&key credential capabilities lifetime
                                      (leaf-extensions '()) (extensions '())
                                      sig-sk sig-pk)
  "Generate a fresh KeyPackage.  SIG-SK/SIG-PK default to a fresh pair."
  (unless sig-sk
    (multiple-value-setq (sig-sk sig-pk) (generate-signature-key-pair)))
  (multiple-value-bind (init-sk init-pk) (hpke-generate-key-pair)
    (multiple-value-bind (leaf-sk leaf-pk) (hpke-generate-key-pair)
      (let* ((ln (sign-leaf-node
                  (make-leaf-node :encryption-key leaf-pk :signature-key sig-pk
                                  :credential credential :capabilities capabilities
                                  :source +lns-key-package+ :lifetime lifetime
                                  :extensions leaf-extensions)
                  sig-sk))
             (kp (make-key-package :init-key init-pk :leaf-node ln :extensions extensions)))
        (setf (key-package-signature kp)
              (sign-with-label sig-sk "KeyPackageTBS" (key-package-tbs kp)))
        (make-key-package-bundle :key-package kp :init-sk init-sk :leaf-sk leaf-sk :sig-sk sig-sk)))))

(defun key-package-ref (kp)
  (make-key-package-ref (tls-serialize 'key-package kp)))

(defun validate-key-package (kp &key (now (unix-time)))
  "RFC 9420 §10.1 checks that do not depend on a group.  Signals mls-error."
  (unless (= (key-package-version kp) +mls10+) (mls-fail "KeyPackage version"))
  (unless (= (key-package-cipher-suite kp) +cs-x25519-aes128gcm-sha256-ed25519+)
    (mls-fail "unsupported ciphersuite ~D" (key-package-cipher-suite kp)))
  (let ((ln (key-package-leaf-node kp)))
    (unless (= (leaf-node-source ln) +lns-key-package+) (mls-fail "KeyPackage leaf source"))
    (unless (verify-with-label (leaf-node-signature-key ln) "KeyPackageTBS"
                               (key-package-tbs kp) (key-package-signature kp))
      (mls-fail "KeyPackage signature"))
    (unless (verify-leaf-node-signature ln) (mls-fail "KeyPackage leaf signature"))
    (when (octets= (key-package-init-key kp) (leaf-node-encryption-key ln))
      (mls-fail "init_key equals leaf encryption_key"))
    (let ((lt (leaf-node-lifetime ln)))
      (when (and now (not (<= (lifetime-not-before lt) now (lifetime-not-after lt))))
        (mls-fail "KeyPackage lifetime does not cover now")))
    (%validate-leaf-extensions-advertised ln))
  kp)

(defparameter +default-extension-types+ '(1 2 3 4 5))
(defparameter +default-proposal-types+ '(1 2 3 4 5 6 7))

(defun %validate-leaf-extensions-advertised (ln)
  (let ((advertised (capabilities-extensions (leaf-node-capabilities ln))))
    (dolist (e (leaf-node-extensions ln))
      (unless (or (member (extension-type e) advertised)
                  (member (extension-type e) +default-extension-types+))
        (mls-fail "leaf uses unadvertised extension ~D" (extension-type e))))))

(defun %leaf-supports-required (ln required-caps)
  (let ((caps (leaf-node-capabilities ln)))
    (and (every (lambda (x) (or (member x +default-extension-types+)
                                (member x (capabilities-extensions caps))))
                (required-capabilities-extension-types required-caps))
         (every (lambda (x) (or (member x +default-proposal-types+)
                                (member x (capabilities-proposals caps))))
                (required-capabilities-proposal-types required-caps))
         (every (lambda (x) (member x (capabilities-credentials caps)))
                (required-capabilities-credential-types required-caps)))))

(defun extensions-required-capabilities (extensions)
  (let ((d (extension-data-of extensions +ext-required-capabilities+)))
    (and d (tls-deserialize 'required-capabilities d))))

(defun validate-leaf-for-group (ln extensions tree &key replacing-leaf)
  "Group-dependent leaf checks: required capabilities and key uniqueness."
  (%validate-leaf-extensions-advertised ln)
  (let ((rc (extensions-required-capabilities extensions)))
    (when (and rc (not (%leaf-supports-required ln rc)))
      (mls-fail "leaf does not support the group's required capabilities")))
  (loop for i in (rt-leaf-indices tree)
        for other = (rt-leaf tree i)
        unless (eql i replacing-leaf)
          do (when (octets= (leaf-node-signature-key other) (leaf-node-signature-key ln))
               (mls-fail "duplicate signature key"))
             (when (octets= (leaf-node-encryption-key other) (leaf-node-encryption-key ln))
               (mls-fail "duplicate encryption key"))))

;;; ---------------------------------------------------------------------------
;;; Group creation (§11)

(defun %init-epoch (g joiner-secret psk-secret)
  "Install epoch secrets and a fresh secret tree derived from JOINER-SECRET."
  (let* ((gc (mls-group-context g))
         (secrets (epoch-secrets-from-joiner joiner-secret psk-secret (group-context-octets gc))))
    (setf (mls-group-secrets g) secrets
          (mls-group-secret-tree g) (make-secret-tree (epoch-secrets-encryption-secret secrets)
                                                      (rt-n-leaves (mls-group-tree g)))
          (mls-group-proposals g) '())
    g))

(defun create-group (&key group-id leaf-node sig-sk leaf-sk (extensions '()))
  "A one-member group at epoch 0.  LEAF-NODE must be signed, source key_package
or (as RFC 9420 allows for the creator) any source."
  (let* ((tree (new-ratchet-tree-with-leaf leaf-node))
         (gc (make-group-context :version +mls10+
                                 :cipher-suite +cs-x25519-aes128gcm-sha256-ed25519+
                                 :group-id group-id :epoch 0
                                 :tree-hash (rt-tree-hash tree)
                                 :confirmed-transcript-hash (make-octets 0)
                                 :extensions extensions))
         (g (make-mls-group :context gc :tree tree :own-leaf 0 :sig-sk sig-sk
                            :node-sks (let ((h (make-hash-table))) (setf (gethash 0 h) leaf-sk) h))))
    (%init-epoch g (joiner-secret-from (random-octets +nh+) (zero-secret) (group-context-octets gc))
                 (zero-secret))
    (let ((tag (mls-mac (epoch-secrets-confirmation-key (mls-group-secrets g))
                        (group-context-confirmed-transcript-hash gc))))
      (setf (mls-group-confirmation-tag g) tag
            (mls-group-interim-hash g) (interim-transcript-hash-next
                                        (group-context-confirmed-transcript-hash gc) tag)))
    g))

;;; ---------------------------------------------------------------------------
;;; Applying proposals (§12.3)

(defstruct applied
  tree extensions
  (joiners '())           ; list of (leaf-index . key-package)
  (removed '())           ; leaf indices removed
  path-required
  self-removed
  (psks '()))             ; PreSharedKeyIDs, in list order

(defun %proposal-requires-path (p)
  (member (proposal-type p)
          (list +prop-update+ +prop-remove+ +prop-external-init+ +prop-group-context-extensions+
                +prop-self-remove+)))

(defun apply-proposals (g proposals committer)
  "PROPOSALS is a list of (proposal . sender-leaf-index).  Validates the list
(§12.2) and returns an APPLIED on a copy of the tree."
  (let* ((tree (copy-rt (mls-group-tree g)))
         (extensions (mls-group-extensions g))
         (result (make-applied))
         (by-type (lambda (ty) (remove-if-not (lambda (ps) (= (proposal-type (car ps)) ty)) proposals)))
         (touched '()))
    ;; list validation
    (when (> (length (funcall by-type +prop-group-context-extensions+)) 1)
      (mls-fail "multiple GroupContextExtensions proposals"))
    (when (funcall by-type +prop-external-init+) (mls-fail "ExternalInit in a member commit"))
    (when (and (funcall by-type +prop-reinit+) (> (length proposals) 1))
      (mls-fail "ReInit with other proposals"))
    (when (funcall by-type +prop-reinit+) (mls-fail "ReInit is not supported"))
    (let ((ids (mapcar (lambda (ps) (tls-serialize 'pre-shared-key-id (proposal-psk (car ps))))
                       (funcall by-type +prop-psk+))))
      (unless (= (length ids) (length (remove-duplicates ids :test #'octets=)))
        (mls-fail "duplicate PreSharedKey proposals"))
      (setf (applied-psks result) (mapcar (lambda (ps) (proposal-psk (car ps)))
                                          (funcall by-type +prop-psk+))))
    ;; 1. GroupContextExtensions
    (let ((gce (first (funcall by-type +prop-group-context-extensions+))))
      (when gce (setf extensions (proposal-extensions (car gce)))))
    ;; draft: AppDataUpdate applies to the (possibly replaced) extensions
    (let ((updates (funcall by-type +prop-app-data-update+)))
      (when updates
        (let ((ids (mapcar (lambda (ps) (proposal-component-id (car ps))) updates)))
          (unless (= (length ids) (length (remove-duplicates ids)))
            (mls-fail "two AppDataUpdate operations for one component")))
        (let ((dict (or (extensions-app-data extensions) '())))
          (dolist (ps updates)
            (let ((p (car ps)))
              (setf dict (app-data-put dict (proposal-component-id p)
                                       (if (= (proposal-operation p) 1) (proposal-data p) nil)))))
          (setf extensions (%extensions-put extensions (app-data-extension dict))))))
    ;; 2. Update
    (dolist (ps (funcall by-type +prop-update+))
      (destructuring-bind (p . sender) ps
        (when (eql sender committer) (mls-fail "committer's own Update proposal"))
        (when (member sender touched) (mls-fail "two Update/Remove for leaf ~D" sender))
        (push sender touched)
        (let ((ln (proposal-leaf-node p)))
          (unless (= (leaf-node-source ln) +lns-update+) (mls-fail "Update leaf source"))
          (unless (verify-leaf-node-signature ln :group-id (mls-group-id g) :leaf-index sender)
            (mls-fail "Update leaf signature"))
          (validate-leaf-for-group ln extensions tree :replacing-leaf sender)
          (rt-update-leaf tree sender ln))))
    ;; 3. Remove (and SelfRemove)
    (dolist (ps proposals)
      (destructuring-bind (p . sender) ps
        (let ((victim (cond ((= (proposal-type p) +prop-remove+) (proposal-removed p))
                            ((= (proposal-type p) +prop-self-remove+) sender))))
          (when victim
            (when (eql victim committer) (mls-fail "commit removes its committer"))
            (unless (and (< victim (rt-n-leaves tree)) (rt-leaf tree victim))
              (mls-fail "Remove of blank leaf ~D" victim))
            (when (member victim touched) (mls-fail "two Update/Remove for leaf ~D" victim))
            (push victim touched)
            (push victim (applied-removed result))
            (when (eql victim (mls-group-own-leaf g)) (setf (applied-self-removed result) t))
            (rt-remove-leaf tree victim)))))
    (rt-truncate tree)
    ;; 4. Add, in list order
    (let ((seen-sig-keys '()))
      (dolist (ps (funcall by-type +prop-add+))
        (let* ((kp (proposal-key-package (car ps)))
               (ln (key-package-leaf-node kp)))
          (validate-key-package kp :now nil)
          (when (member (leaf-node-signature-key ln) seen-sig-keys :test #'octets=)
            (mls-fail "two Adds for the same client"))
          (push (leaf-node-signature-key ln) seen-sig-keys)
          (validate-leaf-for-group ln extensions tree)
          (let ((idx (rt-add-leaf tree ln)))
            (push (cons idx kp) (applied-joiners result))))))
    (setf (applied-joiners result) (nreverse (applied-joiners result))
          (applied-tree result) tree
          (applied-extensions result) extensions
          (applied-path-required result)
          (or (null proposals) (some (lambda (ps) (%proposal-requires-path (car ps))) proposals)))
    ;; every member must support the (new) required capabilities
    (let ((rc (extensions-required-capabilities extensions)))
      (when rc
        (dolist (i (rt-leaf-indices tree))
          (unless (%leaf-supports-required (rt-leaf tree i) rc)
            (mls-fail "member ~D does not support required capabilities" i)))))
    result))

(defun %lookup-psk (g id)
  (ecase (pre-shared-key-id-type id)
    (1 (or (cdr (assoc (pre-shared-key-id-psk-id id) (mls-group-external-psks g) :test #'octets=))
           (mls-fail "unknown external PSK")))
    (2 (unless (octets= (pre-shared-key-id-group-id id) (mls-group-id g))
         (mls-fail "resumption PSK from another group"))
       (or (cdr (assoc (pre-shared-key-id-epoch id) (mls-group-resumption-psks g)))
           (mls-fail "unknown resumption PSK epoch ~D" (pre-shared-key-id-epoch id))))))

(defun %psk-secret-for (g ids)
  (psk-secret (mapcar (lambda (id) (cons id (%lookup-psk g id))) ids)))

(defun %carry-psk-state (old new)
  "NEW inherits OLD's PSK stores, plus OLD's own resumption secret."
  (setf (mls-group-external-psks new) (mls-group-external-psks old)
        (mls-group-resumption-psks new)
        (acons (mls-group-epoch old) (epoch-secrets-resumption-psk (mls-group-secrets old))
               (mls-group-resumption-psks old)))
  new)

(defun %extensions-put (extensions ext)
  "Replace an extension of the same type in place, or append (openmls add_or_replace)."
  (if (find-extension extensions (extension-type ext))
      (mapcar (lambda (e) (if (= (extension-type e) (extension-type ext)) ext e)) extensions)
      (append extensions (list ext))))

;;; ---------------------------------------------------------------------------
;;; Creating a commit (§12.4.1)

(defstruct staged-commit
  message                 ; MLSMessage octets (PublicMessage commit)
  welcome                 ; MLSMessage octets (Welcome) or NIL
  group-info              ; GroupInfo struct for the new epoch
  new-group               ; the MLS-GROUP to install once published
  joiners                 ; list of (leaf-index . key-package)
  invitees)               ; Marmot: list of (pubkey-hex . kp-event-id) owed a Welcome

(defun %derive-path (path-secret-0 n)
  "N path secrets starting from PATH-SECRET-0, and the commit secret."
  (let ((secrets (list path-secret-0)))
    (loop repeat (1- n) do (push (derive-secret (first secrets) "path") secrets))
    (values (nreverse secrets) (derive-secret (first secrets) "path"))))

(defun %node-key-pair (path-secret)
  (hpke-derive-key-pair (derive-secret path-secret "node")))

(defun create-commit (g &key (proposals '()) (by-reference '()) (leaf-node-extensions nil)
                             (authenticated-data (make-octets 0)) (force-path t))
  "Build a commit carrying PROPOSALS (inline PROPOSAL structs) plus
BY-REFERENCE (received proposals, as stored in MLS-GROUP-PROPOSALS).
Returns a STAGED-COMMIT; G itself is not modified."
  (let* ((own (mls-group-own-leaf g))
         (all (append (mapcar (lambda (p) (cons p own)) proposals)
                      (mapcar (lambda (rp) (cons (getf rp :proposal) (getf rp :sender))) by-reference)))
         (applied (apply-proposals g all own))
         (tree (applied-tree applied))
         (old-gc (mls-group-context g))
         (new-sks (make-hash-table))
         (path nil) (path-secrets nil) (fdp nil)
         (commit-secret (zero-secret)))
    (when (applied-self-removed applied) (mls-fail "cannot commit our own removal"))
    ;; carry our private keys for nodes that still hold the same public key
    (maphash (lambda (k v) (setf (gethash k new-sks) v)) (mls-group-node-sks g))
    (when (or force-path (applied-path-required applied))
      (rt-blank-path tree own)
      (setf fdp (rt-filtered-direct-path-with-copath tree own))
      (multiple-value-bind (leaf-sk leaf-pk) (hpke-generate-key-pair)
        (multiple-value-bind (secrets csecret) (%derive-path (random-octets +nh+) (max 1 (length fdp)))
          (when fdp (setf path-secrets secrets commit-secret csecret))
          (when (null fdp)
            ;; a one-member tree: no path secrets, commit secret from a fresh secret
            (setf commit-secret (derive-secret (random-octets +nh+) "path")))
          ;; install the new parent keys
          (loop for (p . nil) in fdp
                for ps in path-secrets
                do (multiple-value-bind (sk pk) (%node-key-pair ps)
                     (setf (rt-node tree p) (make-parent-node :encryption-key pk
                                                              :parent-hash (make-octets 0)
                                                              :unmerged-leaves '()))
                     (setf (gethash p new-sks) sk)))
          ;; new leaf
          (let* ((old-leaf (rt-leaf tree own))
                 (leaf-ph (rt-set-path-parent-hashes tree own))
                 (ln (make-leaf-node :encryption-key leaf-pk
                                     :signature-key (leaf-node-signature-key old-leaf)
                                     :credential (leaf-node-credential old-leaf)
                                     :capabilities (leaf-node-capabilities old-leaf)
                                     :source +lns-commit+
                                     :parent-hash leaf-ph
                                     :extensions (or leaf-node-extensions
                                                     (leaf-node-extensions old-leaf)))))
            (sign-leaf-node ln (mls-group-sig-sk g) :group-id (mls-group-id g) :leaf-index own)
            (setf (rt-node tree (* 2 own)) ln)
            (setf (gethash (* 2 own) new-sks) leaf-sk))
          ;; drop keys for nodes no longer on our path or blanked
          (maphash (lambda (k v) (declare (ignore v))
                     (unless (or (= k (* 2 own))
                                 (and (< k (rt-size tree)) (rt-node tree k)
                                      (member k (tm-direct-path (* 2 own) (rt-n-leaves tree)))))
                       (remhash k new-sks)))
                   new-sks))))
    ;; provisional group context
    (let* ((provisional (copy-group-context-with old-gc
                                                 :epoch (1+ (group-context-epoch old-gc))
                                                 :tree-hash (rt-tree-hash tree)
                                                 :extensions (applied-extensions applied)))
           (provisional-octets (group-context-octets provisional))
           (joiner-leaves (mapcar #'car (applied-joiners applied))))
      ;; encrypt path secrets
      (when fdp
        (setf path
              (make-update-path
               :leaf-node (rt-leaf tree own)
               :nodes (loop for (p . c) in fdp
                            for ps in path-secrets
                            collect (make-update-path-node
                                     :encryption-key (parent-node-encryption-key (rt-node tree p))
                                     :encrypted-path-secret
                                     (loop for r in (rt-resolution tree c :exclude-leaves joiner-leaves)
                                           collect (encrypt-with-label
                                                    (%node-public-key tree r) "UpdatePathNode"
                                                    provisional-octets ps)))))))
      (when (and (null fdp) (or force-path (applied-path-required applied)))
        (setf path (make-update-path :leaf-node (rt-leaf tree own) :nodes '())))
      ;; framed content
      (let* ((commit (make-commit
                      :proposals (append (mapcar (lambda (p) (make-proposal-or-ref :proposal p)) proposals)
                                         (mapcar (lambda (rp) (make-proposal-or-ref :reference (getf rp :ref)))
                                                 by-reference))
                      :path path))
             (fc (make-framed-content :group-id (mls-group-id g)
                                      :epoch (group-context-epoch old-gc)
                                      :sender (make-sender :type +sender-member+ :index own)
                                      :authenticated-data authenticated-data
                                      :content-type +content-commit+
                                      :commit commit))
             (signature (sign-framed-content (mls-group-sig-sk g) +wf-public-message+ fc old-gc))
             (confirmed (confirmed-transcript-hash-next (mls-group-interim-hash g)
                                                        +wf-public-message+ fc signature))
             (new-gc (copy-group-context-with provisional :confirmed-transcript-hash confirmed))
             (new-gc-octets (group-context-octets new-gc))
             (joiner (joiner-secret-from (epoch-secrets-init-secret (mls-group-secrets g))
                                         commit-secret new-gc-octets))
             (new (make-mls-group :context new-gc :tree tree :own-leaf own
                                  :sig-sk (mls-group-sig-sk g) :node-sks new-sks)))
        (%carry-psk-state g new)
        (%init-epoch new joiner (%psk-secret-for g (applied-psks applied)))
        (let* ((tag (mls-mac (epoch-secrets-confirmation-key (mls-group-secrets new)) confirmed))
               (auth (make-auth-data :signature signature :confirmation-tag tag))
               (pm (make-public-message
                    :content fc :auth auth
                    :membership-tag (membership-tag (epoch-secrets-membership-key (mls-group-secrets g))
                                                    +wf-public-message+ fc auth old-gc))))
          (setf (mls-group-confirmation-tag new) tag
                (mls-group-interim-hash new) (interim-transcript-hash-next confirmed tag))
          (let* ((gi (make-group-info-for new))
                 (welcome (and (applied-joiners applied)
                               (%make-welcome new gi (applied-joiners applied) fdp path-secrets
                                               (applied-psks applied)))))
            (make-staged-commit
             :message (mls-message-octets +wf-public-message+ pm)
             :welcome (and welcome (mls-message-octets +wf-welcome+ welcome))
             :group-info gi
             :new-group new
             :joiners (applied-joiners applied))))))))

(defun %node-public-key (tree node-index)
  (let ((n (rt-node tree node-index)))
    (if (evenp node-index) (leaf-node-encryption-key n) (parent-node-encryption-key n))))

(defun make-group-info-for (g &key (extensions (list (ratchet-tree-extension (mls-group-tree g)))))
  (let ((gi (make-group-info :group-context (mls-group-context g)
                             :extensions extensions
                             :confirmation-tag (mls-group-confirmation-tag g)
                             :signer (mls-group-own-leaf g))))
    (setf (group-info-signature gi)
          (sign-with-label (mls-group-sig-sk g) "GroupInfoTBS" (group-info-tbs gi)))
    gi))

(defun %make-welcome (new gi joiners fdp path-secrets psks)
  (multiple-value-bind (key nonce) (welcome-key-nonce (epoch-secrets-welcome-secret (mls-group-secrets new)))
    (let ((egi (mls-aead-encrypt key nonce (tls-serialize 'group-info gi) (make-octets 0))))
      (make-welcome
       :cipher-suite +cs-x25519-aes128gcm-sha256-ed25519+
       :encrypted-group-info egi
       :secrets
       (loop for (leaf . kp) in joiners
             collect (let* ((lca-pos (and fdp (position-if (lambda (pc) (tm-is-ancestor (car pc) (* 2 leaf))) fdp)))
                            (gs (make-group-secrets
                                 :joiner-secret (epoch-secrets-joiner-secret (mls-group-secrets new))
                                 :path-secret (and lca-pos (nth lca-pos path-secrets))
                                 :psks psks)))
                       (make-encrypted-group-secrets
                        :new-member (key-package-ref kp)
                        :encrypted-group-secrets
                        (encrypt-with-label (key-package-init-key kp) "Welcome" egi
                                            (tls-serialize 'group-secrets gs)))))))))

;;; ---------------------------------------------------------------------------
;;; Processing a commit (§12.4.2)

(defun %resolve-proposals (g commit sender)
  "Proposals of COMMIT as (proposal . sender) pairs, resolving references."
  (loop for por in (commit-proposals commit)
        collect (if (proposal-or-ref-proposal por)
                    (cons (proposal-or-ref-proposal por) sender)
                    (let ((rp (find (proposal-or-ref-reference por) (mls-group-proposals g)
                                    :key (lambda (x) (getf x :ref)) :test #'octets=)))
                      (unless rp (mls-fail "unknown proposal reference"))
                      (cons (getf rp :proposal) (getf rp :sender))))))

(defun %verify-public-message (g pm)
  "Membership tag + signature against the current epoch.  Returns sender leaf node."
  (let* ((fc (public-message-content pm))
         (sender (framed-content-sender fc))
         (gc (mls-group-context g)))
    (unless (octets= (framed-content-group-id fc) (mls-group-id g)) (mls-fail "wrong group"))
    (unless (= (framed-content-epoch fc) (mls-group-epoch g))
      (mls-fail "epoch ~D, group is at ~D" (framed-content-epoch fc) (mls-group-epoch g)))
    (unless (= (sender-type sender) +sender-member+) (mls-fail "non-member sender not supported"))
    (let ((leaf (mls-group-member-leaf g (sender-index sender))))
      (unless leaf (mls-fail "sender leaf ~D is blank" (sender-index sender)))
      (unless (ct-octets= (membership-tag (epoch-secrets-membership-key (mls-group-secrets g))
                                          +wf-public-message+ fc (public-message-auth pm) gc)
                          (public-message-membership-tag pm))
        (mls-fail "bad membership tag"))
      (unless (verify-framed-content (leaf-node-signature-key leaf) +wf-public-message+ fc gc
                                     (auth-data-signature (public-message-auth pm)))
        (mls-fail "bad signature"))
      leaf)))

(defun merge-update-path (tree committer path)
  "Merge PATH (an UPDATE-PATH from COMMITTER) into TREE in place: blank the
direct path, install the new parent keys and leaf, and check the leaf's parent
hash.  Returns the filtered direct path as (parent . copath-child) pairs."
  (let ((ln (update-path-leaf-node path)))
    (rt-blank-path tree committer)
    (let ((fdp (rt-filtered-direct-path-with-copath tree committer)))
      (unless (= (length fdp) (length (update-path-nodes path)))
        (mls-fail "UpdatePath length ~D, filtered direct path ~D"
                  (length (update-path-nodes path)) (length fdp)))
      (loop for (p . nil) in fdp
            for upn in (update-path-nodes path)
            do (setf (rt-node tree p) (make-parent-node
                                       :encryption-key (update-path-node-encryption-key upn)
                                       :parent-hash (make-octets 0) :unmerged-leaves '())))
      (setf (rt-node tree (* 2 committer)) ln)
      (let ((expected (rt-set-path-parent-hashes tree committer)))
        (unless (and (leaf-node-parent-hash ln) (octets= expected (leaf-node-parent-hash ln)))
          (mls-fail "parent hash mismatch")))
      fdp)))

(defun decrypt-update-path (tree own fdp path node-sks context-octets joiner-leaves)
  "Decrypt the path secret meant for leaf OWN.  NODE-SKS maps node -> private
key (pre-commit).  Returns (values alist-of-(node . sk) commit-secret
path-secret-at-first-node-we-share)."
  (when (null fdp) (return-from decrypt-update-path (values '() nil nil)))
  (let ((pos (position-if (lambda (pc) (tm-is-ancestor (cdr pc) (* 2 own))) fdp)))
    (unless pos (mls-fail "no path node covers our leaf"))
    (let* ((copath (cdr (nth pos fdp)))
           (res (rt-resolution tree copath :exclude-leaves joiner-leaves))
           (ri (position-if (lambda (r) (gethash r node-sks)) res))
           (cts (update-path-node-encrypted-path-secret (nth pos (update-path-nodes path)))))
      (unless ri (mls-fail "no private key in the copath resolution"))
      (unless (= (length cts) (length res)) (mls-fail "ciphertext count mismatch"))
      (let* ((ps (decrypt-with-label (gethash (nth ri res) node-sks) "UpdatePathNode"
                                     context-octets (nth ri cts)))
             (first-ps ps)
             (keys '()))
        (loop for (p . nil) in (nthcdr pos fdp)
              do (multiple-value-bind (nsk npk) (%node-key-pair ps)
                   (unless (octets= npk (parent-node-encryption-key (rt-node tree p)))
                     (mls-fail "derived path key mismatch at node ~D" p))
                   (push (cons p nsk) keys))
                 (setf ps (derive-secret ps "path")))
        (values (nreverse keys) ps first-ps)))))

(defun process-commit (g pm)
  "Verify and process a PublicMessage commit; returns the new group.  G is
not modified."
  (%verify-public-message g pm)
  (process-commit-content g (public-message-content pm) (public-message-auth pm)
                          +wf-public-message+))

(defun process-commit-content (g fc auth wire-format)
  "Process commit content FC/AUTH whose signature (and membership tag, for a
PublicMessage) has already been verified."
  (let* ((committer (sender-index (framed-content-sender fc)))
         (commit (framed-content-commit fc))
         (proposals (%resolve-proposals g commit committer))
         (applied (apply-proposals g proposals committer))
         (tree (applied-tree applied))
         (own (mls-group-own-leaf g))
         (old-gc (mls-group-context g))
         (path (commit-path commit))
         (new-sks (make-hash-table))
         (commit-secret (zero-secret)))
    (when (and (applied-path-required applied) (null path)) (mls-fail "commit requires a path"))
    (when (applied-self-removed applied)
      (let ((out (copy-mls-group g)))
        (setf (mls-group-active out) nil)
        (return-from process-commit-content out)))
    (maphash (lambda (k v) (setf (gethash k new-sks) v)) (mls-group-node-sks g))
    (when path
      (let ((ln (update-path-leaf-node path)))
        (unless (= (leaf-node-source ln) +lns-commit+) (mls-fail "path leaf source"))
        (unless (verify-leaf-node-signature ln :group-id (mls-group-id g) :leaf-index committer)
          (mls-fail "path leaf signature"))
        (validate-leaf-for-group ln (applied-extensions applied) tree :replacing-leaf committer)
        (let ((fdp (merge-update-path tree committer path)))
          (dolist (p (tm-direct-path (* 2 committer) (rt-n-leaves tree)))
            (remhash p new-sks))
          (when fdp
            (let ((ctx (group-context-octets
                        (copy-group-context-with old-gc
                                                 :epoch (1+ (group-context-epoch old-gc))
                                                 :tree-hash (rt-tree-hash tree)
                                                 :extensions (applied-extensions applied)))))
              (multiple-value-bind (keys csecret)
                  (decrypt-update-path tree own fdp path (mls-group-node-sks g) ctx
                                       (mapcar #'car (applied-joiners applied)))
                (loop for (p . sk) in keys do (setf (gethash p new-sks) sk))
                (setf commit-secret csecret)))))))
    (maphash (lambda (k v) (declare (ignore v))
               (unless (and (< k (rt-size tree)) (rt-node tree k)) (remhash k new-sks)))
             new-sks)
    (let* ((confirmed (confirmed-transcript-hash-next (mls-group-interim-hash g) wire-format
                                                      fc (auth-data-signature auth)))
           (new-gc (copy-group-context-with old-gc
                                            :epoch (1+ (group-context-epoch old-gc))
                                            :tree-hash (rt-tree-hash tree)
                                            :confirmed-transcript-hash confirmed
                                            :extensions (applied-extensions applied)))
           (joiner (joiner-secret-from (epoch-secrets-init-secret (mls-group-secrets g))
                                       commit-secret (group-context-octets new-gc)))
           (new (make-mls-group :context new-gc :tree tree :own-leaf own
                                :sig-sk (mls-group-sig-sk g) :node-sks new-sks)))
      (%carry-psk-state g new)
      (%init-epoch new joiner (%psk-secret-for g (applied-psks applied)))
      (let ((tag (mls-mac (epoch-secrets-confirmation-key (mls-group-secrets new)) confirmed)))
        (unless (ct-octets= tag (auth-data-confirmation-tag auth))
          (mls-fail "bad confirmation tag"))
        (setf (mls-group-confirmation-tag new) tag
              (mls-group-interim-hash new) (interim-transcript-hash-next confirmed tag)))
      new)))

;;; ---------------------------------------------------------------------------
;;; Joining from a Welcome (§12.4.3.1)

(defun join-from-welcome (welcome bundle &key ratchet-tree-nodes external-psks)
  "WELCOME is a WELCOME struct; BUNDLE the KEY-PACKAGE-BUNDLE it targets.
Returns (values group group-info)."
  (let* ((kp (key-package-bundle-key-package bundle))
         (ref (key-package-ref kp))
         (egs (find ref (welcome-secrets welcome) :key #'encrypted-group-secrets-new-member
                                                  :test #'octets=)))
    (unless (= (welcome-cipher-suite welcome) +cs-x25519-aes128gcm-sha256-ed25519+)
      (mls-fail "Welcome ciphersuite"))
    (unless egs (mls-fail "Welcome is not for this KeyPackage"))
    (let* ((gs (tls-deserialize 'group-secrets
                                (decrypt-with-label (key-package-bundle-init-sk bundle) "Welcome"
                                                    (welcome-encrypted-group-info welcome)
                                                    (encrypted-group-secrets-encrypted-group-secrets egs))))
           (psk (psk-secret (mapcar (lambda (id)
                                      (unless (= (pre-shared-key-id-type id) 1)
                                        (mls-fail "resumption PSK in Welcome is not supported"))
                                      (cons id (or (cdr (assoc (pre-shared-key-id-psk-id id) external-psks
                                                               :test #'octets=))
                                                   (mls-fail "unknown external PSK"))))
                                    (group-secrets-psks gs))))
           (member (hkdf-extract (group-secrets-joiner-secret gs) psk))
           (welcome-secret (derive-secret member "welcome")))
      (multiple-value-bind (key nonce) (welcome-key-nonce welcome-secret)
        (let* ((gi (tls-deserialize 'group-info
                                    (mls-aead-decrypt key nonce (welcome-encrypted-group-info welcome)
                                                      (make-octets 0))))
               (gc (group-info-group-context gi))
               (nodes (or ratchet-tree-nodes
                          (let ((d (extension-data-of (group-info-extensions gi) +ext-ratchet-tree+)))
                            (unless d (mls-fail "no ratchet tree in GroupInfo"))
                            (decode-exactly d #'decode-ratchet-tree "ratchet_tree"))))
               (tree (make-ratchet-tree-from-nodes nodes)))
          (unless (= (group-context-cipher-suite gc) +cs-x25519-aes128gcm-sha256-ed25519+)
            (mls-fail "GroupInfo ciphersuite"))
          ;; signer
          (let ((signer (and (< (group-info-signer gi) (rt-n-leaves tree))
                             (rt-leaf tree (group-info-signer gi)))))
            (unless signer (mls-fail "GroupInfo signer is blank"))
            (unless (verify-with-label (leaf-node-signature-key signer) "GroupInfoTBS"
                                       (group-info-tbs gi) (group-info-signature gi))
              (mls-fail "GroupInfo signature")))
          ;; tree validation
          (unless (octets= (rt-tree-hash tree) (group-context-tree-hash gc)) (mls-fail "tree hash mismatch"))
          (multiple-value-bind (ok why) (rt-verify-parent-hashes tree)
            (unless ok (mls-fail "~A" why)))
          (validate-tree-leaves tree (group-context-group-id gc) (group-context-extensions gc))
          ;; our leaf
          (let* ((own-ln (key-package-leaf-node kp))
                 (own (loop for i in (rt-leaf-indices tree)
                            when (octets= (tls-serialize 'leaf-node (rt-leaf tree i))
                                          (tls-serialize 'leaf-node own-ln))
                              return i)))
            (unless own (mls-fail "our leaf is not in the tree"))
            (let ((sks (make-hash-table)))
              (setf (gethash (* 2 own) sks) (key-package-bundle-leaf-sk bundle))
              (when (group-secrets-path-secret gs)
                (let* ((n (rt-n-leaves tree))
                       (lca (let ((a (* 2 own)) (b (* 2 (group-info-signer gi))))
                              (find-if (lambda (p) (tm-is-ancestor p b)) (tm-direct-path a n))))
                       (ps (group-secrets-path-secret gs)))
                  (dolist (p (member lca (tm-direct-path (* 2 own) n)))
                    (when (rt-node tree p)
                      (multiple-value-bind (sk pk) (%node-key-pair ps)
                        (unless (octets= pk (parent-node-encryption-key (rt-node tree p)))
                          (mls-fail "Welcome path secret does not match node ~D" p))
                        (setf (gethash p sks) sk))
                      (setf ps (derive-secret ps "path"))))))
              (let ((g (make-mls-group :context gc :tree tree :own-leaf own
                                       :sig-sk (key-package-bundle-sig-sk bundle) :node-sks sks
                                       :external-psks external-psks)))
                (%init-epoch g (group-secrets-joiner-secret gs) psk)
                (let ((tag (mls-mac (epoch-secrets-confirmation-key (mls-group-secrets g))
                                    (group-context-confirmed-transcript-hash gc))))
                  (unless (ct-octets= tag (group-info-confirmation-tag gi))
                    (mls-fail "GroupInfo confirmation tag"))
                  (setf (mls-group-confirmation-tag g) tag
                        (mls-group-interim-hash g)
                        (interim-transcript-hash-next (group-context-confirmed-transcript-hash gc) tag)))
                (values g gi)))))))))

(defun validate-tree-leaves (tree group-id extensions)
  (let ((sig-keys '()) (enc-keys '()))
    (dolist (i (rt-leaf-indices tree))
      (let ((ln (rt-leaf tree i)))
        (unless (if (= (leaf-node-source ln) +lns-key-package+)
                    (verify-leaf-node-signature ln)
                    (verify-leaf-node-signature ln :group-id group-id :leaf-index i))
          (mls-fail "leaf ~D signature" i))
        (%validate-leaf-extensions-advertised ln)
        (let ((rc (extensions-required-capabilities extensions)))
          (when (and rc (not (%leaf-supports-required ln rc)))
            (mls-fail "leaf ~D lacks required capabilities" i)))
        (when (member (leaf-node-signature-key ln) sig-keys :test #'octets=) (mls-fail "duplicate signature key"))
        (when (member (leaf-node-encryption-key ln) enc-keys :test #'octets=) (mls-fail "duplicate encryption key"))
        (push (leaf-node-signature-key ln) sig-keys)
        (push (leaf-node-encryption-key ln) enc-keys)))
    ;; parent encryption keys unique too
    (loop for p from 1 below (rt-size tree) by 2
          for node = (rt-node tree p)
          when node
            do (when (member (parent-node-encryption-key node) enc-keys :test #'octets=)
                 (mls-fail "duplicate encryption key"))
               (push (parent-node-encryption-key node) enc-keys))
    t))

;;; ---------------------------------------------------------------------------
;;; Application messages and standalone proposals

(defun create-application-message (g plaintext &key (authenticated-data (make-octets 0)) (padding 0))
  "Encrypt PLAINTEXT as a PrivateMessage; returns MLSMessage octets.  Mutates
G's secret tree (consumes a generation)."
  (unless (mls-group-active g) (mls-fail "not a member"))
  (let* ((fc (make-framed-content :group-id (mls-group-id g) :epoch (mls-group-epoch g)
                                  :sender (make-sender :type +sender-member+ :index (mls-group-own-leaf g))
                                  :authenticated-data authenticated-data
                                  :content-type +content-application+
                                  :application-data plaintext))
         (auth (make-auth-data :signature (sign-framed-content (mls-group-sig-sk g) +wf-private-message+
                                                               fc (mls-group-context g)))))
    (mls-message-octets +wf-private-message+
                        (encrypt-private-message fc auth (mls-group-secret-tree g)
                                                 (epoch-secrets-sender-data-secret (mls-group-secrets g))
                                                 :padding padding))))

(defun create-proposal-message (g proposal &key (authenticated-data (make-octets 0)))
  "A standalone PublicMessage proposal.  Returns (values octets ref)."
  (let* ((fc (make-framed-content :group-id (mls-group-id g) :epoch (mls-group-epoch g)
                                  :sender (make-sender :type +sender-member+ :index (mls-group-own-leaf g))
                                  :authenticated-data authenticated-data
                                  :content-type +content-proposal+
                                  :proposal proposal))
         (gc (mls-group-context g))
         (auth (make-auth-data :signature (sign-framed-content (mls-group-sig-sk g) +wf-public-message+ fc gc)))
         (pm (make-public-message :content fc :auth auth
                                  :membership-tag (membership-tag (epoch-secrets-membership-key (mls-group-secrets g))
                                                                  +wf-public-message+ fc auth gc))))
    (let ((octets (mls-message-octets +wf-public-message+ pm)))
      ;; the proposer retains its own proposal, so a commit can reference it
      (%store-proposal g fc auth +wf-public-message+ octets)
      (values octets (make-proposal-ref (authenticated-content-octets +wf-public-message+ fc auth))))))

(defun process-message (g message-octets)
  "Process one MLSMessage addressed to group G.  Returns a plist:
  (:type :application :sender leaf :data octets :authenticated-data ad)
  (:type :proposal :sender leaf :proposal p :ref ref)   ; also stored in G
  (:type :commit :sender leaf :new-group g2 :commit c)"
  (let* ((msg (tls-deserialize 'mls-message message-octets))
         (wf (mls-message-wire-format msg)))
    (cond
      ((= wf +wf-private-message+)
       (let ((pm (mls-message-body msg)))
         (unless (octets= (private-message-group-id pm) (mls-group-id g)) (mls-fail "wrong group"))
         (unless (= (private-message-epoch pm) (mls-group-epoch g))
           (mls-fail "epoch ~D, group is at ~D" (private-message-epoch pm) (mls-group-epoch g)))
         (multiple-value-bind (fc auth)
             (decrypt-private-message pm (mls-group-secret-tree g)
                                      (epoch-secrets-sender-data-secret (mls-group-secrets g)))
           (let* ((sender (sender-index (framed-content-sender fc)))
                  (leaf (mls-group-member-leaf g sender)))
             (unless leaf (mls-fail "sender leaf ~D is blank" sender))
             (unless (verify-framed-content (leaf-node-signature-key leaf) +wf-private-message+ fc
                                            (mls-group-context g) (auth-data-signature auth))
               (mls-fail "bad signature"))
             (ecase (framed-content-content-type fc)
               (1 (list :type :application :sender sender :sender-leaf leaf
                        :data (framed-content-application-data fc)
                        :authenticated-data (framed-content-authenticated-data fc)))
               (2 (%store-proposal g fc auth +wf-private-message+ message-octets))
               (3 (list :type :commit :sender sender :commit (framed-content-commit fc)
                        :new-group (process-commit-content g fc auth +wf-private-message+))))))))
      ((= wf +wf-public-message+)
       (let* ((pm (mls-message-body msg))
              (fc (public-message-content pm)))
         (case (framed-content-content-type fc)
           (2 (%verify-public-message g pm)
            (%store-proposal g fc (public-message-auth pm) +wf-public-message+ message-octets))
           (3 (list :type :commit :sender (sender-index (framed-content-sender fc))
                    :commit (framed-content-commit fc)
                    :new-group (process-commit g pm)))
           (t (mls-fail "application data in a PublicMessage")))))
      (t (mls-fail "unexpected wire format ~D for a group message" wf)))))

(defun %store-proposal (g fc auth wire-format &optional message-octets)
  (let* ((ref (make-proposal-ref (authenticated-content-octets wire-format fc auth)))
         (entry (list :ref ref :proposal (framed-content-proposal fc)
                      :sender (sender-index (framed-content-sender fc))
                      :digest (and message-octets (sha256 message-octets)))))
    (unless (find ref (mls-group-proposals g) :key (lambda (x) (getf x :ref)) :test #'octets=)
      (setf (mls-group-proposals g) (append (mls-group-proposals g) (list entry))))
    (list* :type :proposal entry)))
