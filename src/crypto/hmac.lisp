;;;; hmac.lisp — HMAC (RFC 2104) and HKDF (RFC 5869)

(in-package #:cl-marmot)

(defun hmac (hash block-size key data)
  "HMAC over the one-shot digest function HASH with the given BLOCK-SIZE."
  (let* ((key (ensure-octets key))
         (data (ensure-octets data))
         (k (if (> (length key) block-size) (funcall hash key) key))
         (ipad (make-octets block-size :initial-element #x36))
         (opad (make-octets block-size :initial-element #x5c)))
    (dotimes (i (length k))
      (setf (aref ipad i) (logxor (aref ipad i) (aref k i))
            (aref opad i) (logxor (aref opad i) (aref k i))))
    (funcall hash (concat-octets opad (funcall hash (concat-octets ipad data))))))

(defun hmac-sha256 (key data)
  "HMAC-SHA-256 (32 octets)."
  (hmac #'sha256 64 key data))

(defun hmac-sha512 (key data)
  "HMAC-SHA-512 (64 octets)."
  (hmac #'sha512 128 key data))

(defun hmac-sha384 (key data)
  "HMAC-SHA-384 (48 octets)."
  (hmac #'sha384 128 key data))

(defun hkdf-extract (salt ikm)
  "HKDF-Extract with HMAC-SHA-256.  A NIL or empty SALT means 32 zero octets."
  (hmac-sha256 (if (or (null salt) (zerop (length salt))) (make-octets 32) salt)
               ikm))

(defun hkdf-expand (prk info length)
  "HKDF-Expand with HMAC-SHA-256: LENGTH octets of output keying material."
  (unless (<= 0 length (* 255 32))
    (crypto-fail "hkdf-expand: length ~D out of range" length))
  (let ((out (make-octets length))
        (info (if info (ensure-octets info) (make-octets 0)))
        (prev (make-octets 0))
        (pos 0))
    (loop for counter from 1
          while (< pos length)
          do (setf prev (hmac-sha256 prk (concat-octets prev info (octets counter))))
             (replace out prev :start1 pos)
             (incf pos (length prev)))
    out))
