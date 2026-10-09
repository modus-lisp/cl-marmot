;;;; bridge.lisp — cl-marmot's crypto vocabulary over the modus-lisp libraries
;;;;
;;;;   natrium         SHA-2, HMAC, HKDF, ChaCha20(-Poly1305), X25519, Ed25519,
;;;;                   CSPRNG — constant-time on secret-key paths
;;;;   seal            AES-GCM (MLS ciphersuite 0x0001's AEAD)
;;;;   secp256k1-fast  BIP-340 Schnorr (constant-time key and signing paths)
;;;;
;;;; The names and conventions below are the ones the MLS and Marmot code (and
;;;; the official test vectors) are written against: AEAD ciphertexts carry the
;;;; tag appended, authentication failures signal AEAD-ERROR rather than
;;;; returning NIL, and verifiers return NIL — never signal — on malformed input.

(in-package #:cl-marmot)

;;; Hashing and key derivation

(defun sha256 (data) (natrium:sha256 (ensure-octets data)))
(defun sha384 (data) (natrium:sha384 (ensure-octets data)))
(defun sha512 (data) (natrium:sha512 (ensure-octets data)))
(defun hmac-sha256 (key data) (natrium:hmac-sha256 (ensure-octets key) (ensure-octets data)))
(defun hmac-sha512 (key data) (natrium:hmac-sha512 (ensure-octets key) (ensure-octets data)))

(defun hkdf-extract (salt ikm)
  "HKDF-SHA256 Extract.  A NIL or empty SALT means 32 zero bytes."
  (natrium:hkdf-extract #'natrium:hmac-sha256 32 (if salt (ensure-octets salt) (make-octets 0))
                        (ensure-octets ikm)))

(defun hkdf-expand (prk info length)
  (natrium:hkdf-expand #'natrium:hmac-sha256 32 (ensure-octets prk) (ensure-octets info) length))

;;; ChaCha20 / Poly1305 (RFC 8439)

(defun chacha20-xor (key nonce data &key (counter 0))
  (natrium:chacha20 (ensure-octets key) (ensure-octets nonce) (ensure-octets data) :counter counter))

(defun poly1305 (key message) (natrium:poly1305-mac (ensure-octets key) (ensure-octets message)))

(defun chacha20-poly1305-encrypt (key nonce plaintext aad)
  "Returns ciphertext || tag."
  (multiple-value-bind (ct tag)
      (natrium:chacha20-poly1305-encrypt (ensure-octets key) (ensure-octets nonce)
                                         (ensure-octets plaintext) (ensure-octets aad))
    (concat-octets ct tag)))

(defun chacha20-poly1305-decrypt (key nonce ciphertext aad)
  "CIPHERTEXT is ciphertext || tag.  Signals AEAD-ERROR on failure."
  (let ((ciphertext (ensure-octets ciphertext)))
    (when (< (length ciphertext) 16) (error 'aead-error))
    (or (natrium:chacha20-poly1305-decrypt (ensure-octets key) (ensure-octets nonce)
                                           (subseq-octets ciphertext 0 (- (length ciphertext) 16))
                                           (subseq-octets ciphertext (- (length ciphertext) 16))
                                           (ensure-octets aad))
        (error 'aead-error))))

;;; AES-GCM (FIPS 197 / SP 800-38D)

(defun aes-gcm-encrypt (key nonce plaintext aad)
  "Returns ciphertext || tag."
  (let ((r (seal:aes-gcm-encrypt (ensure-octets key) (ensure-octets nonce)
                                 (ensure-octets plaintext) (ensure-octets aad))))
    (concat-octets (coerce-octets (car r)) (coerce-octets (cdr r)))))

(defun aes-gcm-decrypt (key nonce ciphertext aad)
  "CIPHERTEXT is ciphertext || tag.  Signals AEAD-ERROR on failure."
  (let ((ciphertext (ensure-octets ciphertext)))
    (when (< (length ciphertext) 16) (error 'aead-error))
    (let ((pt (seal:aes-gcm-decrypt (ensure-octets key) (ensure-octets nonce)
                                    (subseq-octets ciphertext 0 (- (length ciphertext) 16))
                                    (ensure-octets aad)
                                    (subseq-octets ciphertext (- (length ciphertext) 16)))))
      (if pt (coerce-octets pt) (error 'aead-error)))))

;;; X25519 / Ed25519

(defun x25519 (scalar u)
  "RFC 7748 X25519.  Signals CRYPTO-ERROR on an all-zero result (a low-order
input), as RFC 9180 requires of DHKEM."
  (let ((out (natrium:x25519 (ensure-octets scalar) (ensure-octets u))))
    (when (every #'zerop out) (crypto-fail "X25519 produced the all-zero value"))
    out))

(defun x25519-base (scalar) (natrium:x25519-base (ensure-octets scalar)))

(defun ed25519-public-key (seed) (natrium:ed25519-public-key (ensure-octets seed)))
(defun ed25519-sign (seed message) (natrium:ed25519-sign (ensure-octets seed) (ensure-octets message)))

(defun ed25519-verify (public message signature)
  (and (typep public '(vector (unsigned-byte 8))) (= (length public) 32)
       (typep signature '(vector (unsigned-byte 8))) (= (length signature) 64)
       (typep message '(vector (unsigned-byte 8)))
       (ignore-errors (natrium:ed25519-verify (ensure-octets public) (ensure-octets message)
                                              (ensure-octets signature)))
       t))

;;; secp256k1 / BIP-340

(defun %secp-n () (secp256k1-fast:secp-init) secp256k1-fast:*secp256k1-n*)

(defun secp256k1-valid-seckey-p (sk)
  (and (typep sk '(vector (unsigned-byte 8))) (= (length sk) 32)
       (< 0 (octets->int-be sk) (%secp-n))))

(defun secp256k1-valid-xonly-p (pk)
  (and (typep pk '(vector (unsigned-byte 8))) (= (length pk) 32)
       (secp256k1-fast.schnorr:lift-x (octets->int-be pk))
       t))

(defun secp256k1-xonly-pubkey (sk)
  (unless (secp256k1-valid-seckey-p sk) (crypto-fail "invalid secp256k1 secret key"))
  (coerce-octets (secp256k1-fast.schnorr:pubkey-xonly (octets->int-be sk))))

(defun bip340-sign (sk message &optional (aux (random-octets 32)))
  (unless (secp256k1-valid-seckey-p sk) (crypto-fail "invalid secp256k1 secret key"))
  (coerce-octets (secp256k1-fast.schnorr:schnorr-sign (octets->int-be sk) (ensure-octets message)
                                                      (ensure-octets aux))))

(defun bip340-verify (pk message signature)
  (and (typep pk '(vector (unsigned-byte 8))) (= (length pk) 32)
       (typep signature '(vector (unsigned-byte 8))) (= (length signature) 64)
       (typep message '(vector (unsigned-byte 8)))
       (ignore-errors (secp256k1-fast.schnorr:schnorr-verify (ensure-octets pk) (ensure-octets message)
                                                             (ensure-octets signature)))
       t))
