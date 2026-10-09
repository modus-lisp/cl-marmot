;;;; components.lisp — Marmot app components (app-components/*.md)
;;;;
;;;; Marmot-owned bytes use the Marmot binary profile: TLS presentation syntax
;;;; with QUIC varint prefixes (8-byte form allowed), canonical-only decoding.
;;;; Each component has ENCODE-/DECODE- functions over plain Lisp values.

(in-package #:cl-marmot)

(define-condition marmot-error (error)
  ((message :initarg :message :reader marmot-error-message))
  (:report (lambda (c s) (format s "Marmot: ~A" (marmot-error-message c)))))

(defun marmot-fail (fmt &rest args)
  (error 'marmot-error :message (apply #'format nil fmt args)))

;;; Component ids (foundation/registries.md)
(defconstant +c-profile+ #x8001)
(defconstant +c-blossom-image+ #x8002)
(defconstant +c-admin-policy+ #x8003)
(defconstant +c-nostr-routing+ #x8004)
(defconstant +c-message-retention+ #x8005)
(defconstant +c-agent-text-stream+ #x8006)
(defconstant +c-avatar-url+ #x8007)
(defconstant +c-encrypted-media-v1+ #x8008)
(defconstant +c-identity-proof+ #x8009)
(defconstant +c-encrypted-media-v2+ #x800b)
(defconstant +c-lifecycle+ #x800c)

(defun %decode-marmot (octets fn what)
  "Decode exactly, translating codec failures into MARMOT-ERROR."
  (handler-case (decode-exactly octets fn what)
    (decode-error (c) (marmot-fail "~A: ~A" what (decode-error-message c)))
    (utf8-error () (marmot-fail "~A: invalid UTF-8" what))))

(defun %strictly-sorted-p (items)
  (loop for (a b) on items while b always (octets< a b)))

;;; 0x8003 marmot.group.admin-policy.v1 — MarmotAdminKeyV1 admins<V>

(defun encode-admin-policy (admins)
  "ADMINS: list of 32-octet keys.  Sorted and de-duplicated here."
  (let ((sorted (sort (remove-duplicates (copy-list admins) :test #'octets=) #'octets<)))
    (with-writer (w) (w-vector w sorted #'w-bytes :quic t))))

(defun decode-admin-policy (octets)
  (let ((admins (%decode-marmot octets (lambda (r) (r-vector r (lambda (r2) (r-bytes r2 32)) :quic t))
                                "admin policy")))
    (unless admins (marmot-fail "admin policy: empty admin list"))
    (unless (%strictly-sorted-p admins) (marmot-fail "admin policy: not sorted/unique"))
    admins))

;;; 0x8004 marmot.transport.nostr.routing.v1

(defun encode-nostr-routing (nostr-group-id relays)
  (let ((sorted (sort (remove-duplicates (copy-list relays) :test #'string=)
                      (lambda (a b) (octets< (string->utf8 a) (string->utf8 b))))))
    (with-writer (w)
      (w-bytes w nostr-group-id)
      (w-vector w sorted (lambda (w2 url) (w-opaque w2 (string->utf8 url) :quic t)) :quic t))))

(defun decode-nostr-routing (octets)
  "Returns (values nostr-group-id relays)."
  (destructuring-bind (gid . urls)
      (%decode-marmot octets
                      (lambda (r)
                        (cons (r-bytes r 32)
                              (r-vector r (lambda (r2) (r-opaque r2 :quic t :max 512)) :quic t)))
                      "nostr routing")
    (unless urls (marmot-fail "routing: empty relay list"))
    (when (> (length urls) 16) (marmot-fail "routing: more than 16 relays"))
    (unless (%strictly-sorted-p urls) (marmot-fail "routing: relays not sorted/unique"))
    (dolist (u urls) (when (zerop (length u)) (marmot-fail "routing: empty relay URL")))
    (values gid (mapcar #'utf8->string urls))))

;;; 0x8001 marmot.group.profile.v1

(defun encode-group-profile (name description)
  (with-writer (w)
    (w-opaque w (string->utf8 name) :quic t)
    (w-opaque w (string->utf8 description) :quic t)))

(defun decode-group-profile (octets)
  "Returns (values name description)."
  (destructuring-bind (name . desc)
      (%decode-marmot octets (lambda (r) (cons (r-opaque r :quic t :max 256) (r-opaque r :quic t :max 4096)))
                      "group profile")
    (values (utf8->string name) (utf8->string desc))))

;;; 0x8005 marmot.group.message-retention.v1

(defun encode-message-retention (secs) (int->octets-be secs 8))

(defun decode-message-retention (octets)
  (unless (= (length octets) 8) (marmot-fail "message retention: not 8 bytes"))
  (octets->int-be octets))

;;; 0x800c marmot.group.lifecycle.v1

(defun encode-lifecycle (state) (octets (ecase state (:active 0) (:disbanded 1))))

(defun decode-lifecycle (octets)
  (cond ((octets= octets (octets 0)) :active)
        ((octets= octets (octets 1)) :disbanded)
        (t (marmot-fail "lifecycle: invalid state bytes"))))

;;; 0x8009 marmot.member.account-identity-proof.v2

(defparameter +identity-proof-content+ "Authorize this MLS leaf key for my Marmot account")

(defun %hex16 (n) (format nil "0x~(~4,'0x~)" n))

(defun identity-proof-event (signer-pubkey created-at mls-signature-key
                             &key (ciphersuite 1) (signature-scheme +signature-scheme-ed25519+))
  (make-nostr-event :pubkey (octets->hex signer-pubkey) :created-at created-at :kind 450
                    :tags (list (list "d" "marmot.account-identity-proof.v2")
                                (list "component" "0x8009")
                                (list "ciphersuite" (%hex16 ciphersuite))
                                (list "signature_scheme" (%hex16 signature-scheme))
                                (list "mls_signature_key" (octets->hex mls-signature-key)))
                    :content +identity-proof-content+))

(defun make-identity-proof (account-sk mls-signature-key &key (created-at (unix-time)))
  "The 104-byte MarmotAuthorizationProof binding MLS-SIGNATURE-KEY to the account."
  (let* ((pub (secp256k1-xonly-pubkey account-sk))
         (ev (identity-proof-event pub created-at mls-signature-key))
         (id (sha256 (string->utf8 (event-id-preimage ev)))))
    (concat-octets pub (int->octets-be created-at 8) (bip340-sign account-sk id))))

(defun verify-identity-proof (proof credential-identity mls-signature-key)
  "foundation/authorization-proofs.md validation + the v2 bindings."
  (unless (= (length proof) 104) (marmot-fail "identity proof: not 104 bytes"))
  (let ((signer (subseq-octets proof 0 32))
        (created (octets->int-be proof :start 32 :end 40))
        (sig (subseq-octets proof 40 104)))
    (unless (secp256k1-valid-xonly-p signer) (marmot-fail "identity proof: invalid signer key"))
    (unless (<= 1 created 9007199254740991) (marmot-fail "identity proof: bad created_at"))
    (unless (octets= signer credential-identity) (marmot-fail "identity proof: signer is not the credential identity"))
    (let ((id (sha256 (string->utf8 (event-id-preimage (identity-proof-event signer created mls-signature-key))))))
      (unless (bip340-verify signer id sig) (marmot-fail "identity proof: bad signature")))
    t))

(defun validate-marmot-leaf (ln)
  "Every Marmot member leaf / KeyPackage leaf: 32-byte valid credential identity,
0x8009 advertised and carried exactly once, and a valid proof."
  (let ((cred (leaf-node-credential ln)))
    (unless (= (credential-type cred) +cred-basic+) (marmot-fail "credential is not basic"))
    (let ((identity (credential-identity cred)))
      (unless (and (= (length identity) 32) (secp256k1-valid-xonly-p identity))
        (marmot-fail "credential identity is not a valid x-only key"))
      (let ((dict (handler-case (extensions-app-data (leaf-node-extensions ln))
                    (decode-error (c) (marmot-fail "leaf app_data_dictionary: ~A" (decode-error-message c))))))
        (let ((supported (let ((d (app-data-get dict +component-app-components+)))
                           (and d (decode-component-id-list d)))))
          (unless (member +c-identity-proof+ supported) (marmot-fail "leaf does not advertise 0x8009")))
        (let ((proof (app-data-get dict +c-identity-proof+)))
          (unless proof (marmot-fail "leaf has no identity proof"))
          (verify-identity-proof proof identity (leaf-node-signature-key ln)))
        identity))))

(defun leaf-account (ln)
  "The Marmot account (32 octets) of a member leaf."
  (credential-identity (leaf-node-credential ln)))

(defun leaf-supported-components (ln)
  (let* ((dict (extensions-app-data (leaf-node-extensions ln)))
         (d (app-data-get dict +component-app-components+)))
    (and d (decode-component-id-list d))))
