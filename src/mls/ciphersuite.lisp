;;;; ciphersuite.lisp — MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)
;;;;
;;;; HPKE (RFC 9180, base mode only: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
;;;; AES-128-GCM) and the labeled MLS helpers of RFC 9420 §5.  Only ciphersuite
;;;; 0x0001 is implemented — the one every Marmot client MUST support — so the
;;;; parameters are constants rather than a dispatch table.

(in-package #:cl-marmot)

(defconstant +nh+ 32)        ; hash / KDF output
(defconstant +nk+ 16)        ; AEAD key
(defconstant +nn+ 12)        ; AEAD nonce
(defconstant +signature-scheme-ed25519+ #x0807)

(defun mls-hash (octets) (sha256 octets))
(defun mls-mac (key data) (hmac-sha256 key data))
(defun mls-aead-encrypt (key nonce pt aad) (aes-gcm-encrypt key nonce pt aad))
(defun mls-aead-decrypt (key nonce ct aad) (aes-gcm-decrypt key nonce ct aad))

(defparameter +mls-label-prefix+ "MLS 1.0 ")

(defun %mls-label (label)
  "\"MLS 1.0 \" + LABEL; LABEL may be a string or raw octets (exporter labels)."
  (concat-octets (string->utf8 +mls-label-prefix+)
                 (if (stringp label) (string->utf8 label) label)))

;;; RFC 9420 §8: ExpandWithLabel / DeriveSecret

(defun expand-with-label (secret label context length)
  (hkdf-expand secret
               (with-writer (w)
                 (w-u16 w length)
                 (w-opaque w (%mls-label label))
                 (w-opaque w context))
               length))

(defun derive-secret (secret label)
  (expand-with-label secret label (make-octets 0) +nh+))

(defun derive-tree-secret (secret label generation length)
  (expand-with-label secret label (int->octets-be generation 4) length))

;;; §5.2 RefHash

(defun ref-hash (label value)
  (mls-hash (with-writer (w)
              (w-opaque w (string->utf8 label))
              (w-opaque w value))))

(defun make-key-package-ref (key-package-octets)
  (ref-hash "MLS 1.0 KeyPackage Reference" key-package-octets))

(defun make-proposal-ref (authenticated-content-octets)
  (ref-hash "MLS 1.0 Proposal Reference" authenticated-content-octets))

;;; §5.1.2 SignWithLabel

(defun %sign-content (label content)
  (with-writer (w)
    (w-opaque w (%mls-label label))
    (w-opaque w content)))

(defun sign-with-label (signature-private-key label content)
  (ed25519-sign signature-private-key (%sign-content label content)))

(defun verify-with-label (signature-public-key label content signature)
  (and (= (length signature-public-key) 32)
       (ed25519-verify signature-public-key (%sign-content label content) signature)))

(defun generate-signature-key-pair ()
  "Returns (values private-seed public-key)."
  (let ((seed (random-octets 32)))
    (values seed (ed25519-public-key seed))))

;;; ---------------------------------------------------------------------------
;;; HPKE

(defparameter +hpke-kem-suite-id+ (concat-octets (string->utf8 "KEM") (octets #x00 #x20)))
(defparameter +hpke-suite-id+
  (concat-octets (string->utf8 "HPKE") (octets #x00 #x20 #x00 #x01 #x00 #x01)))

(defun %labeled-extract (suite-id salt label ikm)
  (hkdf-extract salt (concat-octets (string->utf8 "HPKE-v1") suite-id
                                    (string->utf8 label) ikm)))

(defun %labeled-expand (suite-id prk label info length)
  (hkdf-expand prk (concat-octets (int->octets-be length 2) (string->utf8 "HPKE-v1")
                                  suite-id (string->utf8 label) info)
               length))

(defun hpke-derive-key-pair (ikm)
  "RFC 9180 §7.1.3 DeriveKeyPair for X25519. Returns (values sk pk)."
  (let* ((prk (%labeled-extract +hpke-kem-suite-id+ (make-octets 0) "dkp_prk" ikm))
         (sk (%labeled-expand +hpke-kem-suite-id+ prk "sk" (make-octets 0) 32)))
    (values sk (x25519-base sk))))

(defun hpke-generate-key-pair ()
  (hpke-derive-key-pair (random-octets 32)))

(defun %hpke-extract-and-expand (dh kem-context)
  (let ((prk (%labeled-extract +hpke-kem-suite-id+ (make-octets 0) "eae_prk" dh)))
    (%labeled-expand +hpke-kem-suite-id+ prk "shared_secret" kem-context 32)))

(defun %hpke-key-schedule (shared-secret info)
  "Base mode.  Returns (values key base-nonce exporter-secret)."
  (let* ((empty (make-octets 0))
         (psk-id-hash (%labeled-extract +hpke-suite-id+ empty "psk_id_hash" empty))
         (info-hash (%labeled-extract +hpke-suite-id+ empty "info_hash" info))
         (ctx (concat-octets (octets 0) psk-id-hash info-hash))
         (secret (%labeled-extract +hpke-suite-id+ shared-secret "secret" empty)))
    (values (%labeled-expand +hpke-suite-id+ secret "key" ctx +nk+)
            (%labeled-expand +hpke-suite-id+ secret "base_nonce" ctx +nn+)
            (%labeled-expand +hpke-suite-id+ secret "exp" ctx +nh+))))

(defun hpke-seal (pk-r info aad plaintext &key ephemeral-ikm)
  "SealBase.  Returns (values enc ciphertext).  EPHEMERAL-IKM pins the
ephemeral key for test vectors."
  (multiple-value-bind (sk-e pk-e)
      (hpke-derive-key-pair (or ephemeral-ikm (random-octets 32)))
    (let* ((dh (x25519 sk-e pk-r))
           (shared (%hpke-extract-and-expand dh (concat-octets pk-e pk-r))))
      (multiple-value-bind (key nonce) (%hpke-key-schedule shared info)
        (values pk-e (aes-gcm-encrypt key nonce plaintext aad))))))

(defun hpke-open (sk-r enc info aad ciphertext)
  "OpenBase.  Signals aead-error on failure."
  (let* ((pk-r (x25519-base sk-r))
         (dh (x25519 sk-r enc))
         (shared (%hpke-extract-and-expand dh (concat-octets enc pk-r))))
    (multiple-value-bind (key nonce) (%hpke-key-schedule shared info)
      (aes-gcm-decrypt key nonce ciphertext aad))))

;;; §5.1.3 EncryptWithLabel

(defun %encrypt-context (label context)
  (with-writer (w)
    (w-opaque w (%mls-label label))
    (w-opaque w context)))

(defun encrypt-with-label (public-key label context plaintext)
  (multiple-value-bind (enc ct)
      (hpke-seal public-key (%encrypt-context label context) (make-octets 0) plaintext)
    (make-hpke-ciphertext :kem-output enc :ciphertext ct)))

(defun decrypt-with-label (private-key label context hpke-ciphertext)
  (hpke-open private-key (hpke-ciphertext-kem-output hpke-ciphertext)
             (%encrypt-context label context) (make-octets 0)
             (hpke-ciphertext-ciphertext hpke-ciphertext)))
