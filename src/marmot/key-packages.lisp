;;;; key-packages.lisp — Marmot KeyPackages and their kind 30443 publication
;;;;
;;;; foundation/key-packages.md, app-components/account-identity-proof-v2.md,
;;;; transports/nostr.md "KeyPackage publication".

(in-package #:cl-marmot)

(defparameter *advertised-extensions* (list +ext-app-data-dictionary+ #xf2d1)
  "MLS extension types in our leaf capabilities.  0xf2d1 is the agent text
stream RECEIVE role, which only means we render the durable final message.")

(defparameter *advertised-proposals* (list +prop-app-data-update+ +prop-self-remove+))

(defparameter *advertised-components*
  (list +c-profile+ +c-blossom-image+ +c-admin-policy+ +c-nostr-routing+ +c-message-retention+
        +c-agent-text-stream+ +c-avatar-url+ +c-encrypted-media-v1+ +c-identity-proof+
        +c-encrypted-media-v2+ +c-lifecycle+)
  "Marmot component ids we advertise in the leaf app_components entry.")

(defconstant +kp-lifetime-span+ 7257600)      ; 84 days
(defconstant +kp-lifetime-max+ 7261200)       ; 84 days + 1 hour (validation bound)

(defun marmot-capabilities ()
  (make-capabilities :versions (list +mls10+)
                     :cipher-suites (list +cs-x25519-aes128gcm-sha256-ed25519+)
                     :extensions *advertised-extensions*
                     :proposals *advertised-proposals*
                     :credentials (list +cred-basic+)))

(defun marmot-leaf-extensions (account-sk mls-signature-key)
  "The LeafNode app_data_dictionary: supported components, (empty) SafeAAD
support list, and the account identity proof."
  (list (app-data-extension
         (list (make-component-data :component-id +component-app-components+
                                    :data (encode-component-id-list *advertised-components*))
               (make-component-data :component-id +component-safe-aad+
                                    :data (encode-component-id-list '()))
               (make-component-data :component-id +c-identity-proof+
                                    :data (make-identity-proof account-sk mls-signature-key))))))

(defun make-marmot-key-package (account-sk &key (last-resort t) (now (unix-time)))
  "A fresh Marmot KeyPackage bundle for the account."
  (multiple-value-bind (sig-sk sig-pk) (generate-signature-key-pair)
    (make-key-package-bundle*
     :credential (basic-credential (secp256k1-xonly-pubkey account-sk))
     :capabilities (marmot-capabilities)
     :lifetime (make-lifetime :not-before (- now 3600) :not-after (+ (- now 3600) +kp-lifetime-span+))
     :leaf-extensions (marmot-leaf-extensions account-sk sig-pk)
     :extensions (if last-resort
                     (list (app-data-extension
                            (list (make-component-data :component-id +component-last-resort-key-package+
                                                       :data (make-octets 0)))))
                     '())
     :sig-sk sig-sk :sig-pk sig-pk)))

(defun key-package-last-resort-p (kp)
  (let ((dict (extensions-app-data (key-package-extensions kp))))
    (and (app-data-get dict +component-last-resort-key-package+) t)))

(defun %id-list-tag (name ids)
  (cons name (mapcar #'%hex16 ids)))

(defun key-package-event (account-sk bundle d-slot)
  "The kind 30443 publication event.  D-SLOT: 32 random octets, reused across
replacements of the same slot."
  (let ((kp (key-package-bundle-key-package bundle)))
    (make-signed-event account-sk
                       :kind 30443
                       :content (octets->base64 (mls-message-octets +wf-key-package+ kp))
                       :tags (list (list "d" (octets->hex d-slot))
                                   (list "mls_protocol_version" "1.0")
                                   (list "i" (octets->hex (key-package-ref kp)))
                                   (%id-list-tag "mls_ciphersuite" (list +cs-x25519-aes128gcm-sha256-ed25519+))
                                   (%id-list-tag "mls_extensions" *advertised-extensions*)
                                   (%id-list-tag "mls_proposals" *advertised-proposals*)
                                   (%id-list-tag "app_components" *advertised-components*)))))

(defun validate-key-package-event (ev &key (now (unix-time)))
  "transports/nostr.md + foundation/key-packages.md.  Returns the KeyPackage."
  (unless (= (ev:event-kind ev) 30443) (marmot-fail "not a KeyPackage event"))
  (unless (verify-event ev) (marmot-fail "KeyPackage event signature"))
  (let ((d (event-tag-value ev "d")))
    (unless (%lower-hex-p d 64) (marmot-fail "bad d tag")))
  (unless (string= (event-tag-value ev "mls_protocol_version") "1.0") (marmot-fail "mls_protocol_version"))
  (dolist (name '("mls_ciphersuite" "mls_extensions" "mls_proposals" "app_components"))
    (let ((vals (event-tag-values ev name)))
      (unless vals (marmot-fail "empty ~A tag" name))
      (unless (= (length vals) (length (remove-duplicates vals :test #'string=)))
        (marmot-fail "duplicate values in ~A" name))))
  (unless (member "0x8009" (event-tag-values ev "app_components") :test #'string=)
    (marmot-fail "app_components does not list 0x8009"))
  (let* ((msg (handler-case (tls-deserialize 'mls-message (base64->octets (ev:event-content ev)))
                (error (c) (marmot-fail "KeyPackage content: ~A" c))))
         (kp (mls-message-body msg)))
    (unless (= (mls-message-wire-format msg) +wf-key-package+) (marmot-fail "content is not mls_key_package"))
    (handler-case (validate-key-package kp :now now)
      (mls-error (c) (marmot-fail "~A" (mls-error-message c))))
    (let* ((ln (key-package-leaf-node kp))
           (lt (leaf-node-lifetime ln)))
      (when (> (- (lifetime-not-after lt) (lifetime-not-before lt)) +kp-lifetime-max+)
        (marmot-fail "KeyPackage lifetime range too long"))
      (let ((identity (validate-marmot-leaf ln)))
        (unless (string= (octets->hex identity) (ev:event-pubkey ev))
          (marmot-fail "KeyPackage credential is not the event author"))))
    (unless (string= (event-tag-value ev "i") (octets->hex (key-package-ref kp)))
      (marmot-fail "i tag does not match the KeyPackageRef"))
    kp))
