;;;; base64.lisp — RFC 4648 §4 base64 (standard alphabet, padded) and bech32
;;;;
;;;; The Marmot Nostr binding requires standard padded base64 and says a field
;;;; that claims to be base64 MUST decode; the decoder here is strict: no
;;;; whitespace, mandatory padding, and non-zero trailing bits are rejected
;;;; (that is what makes the encoding canonical).

(in-package #:cl-marmot)

(define-condition base64-error (error)
  ((string :initarg :string :reader base64-error-string))
  (:report (lambda (c s)
             (format s "Invalid base64 (~D chars)" (length (base64-error-string c))))))

(defparameter +base64-alphabet+
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun octets->base64 (v)
  (let* ((n (length v))
         (out (make-string (* 4 (ceiling n 3))))
         (o 0))
    (loop for i from 0 below n by 3
          do (let* ((b0 (aref v i))
                    (b1 (if (< (+ i 1) n) (aref v (+ i 1)) 0))
                    (b2 (if (< (+ i 2) n) (aref v (+ i 2)) 0))
                    (w (logior (ash b0 16) (ash b1 8) b2)))
               (setf (char out o) (char +base64-alphabet+ (ldb (byte 6 18) w))
                     (char out (+ o 1)) (char +base64-alphabet+ (ldb (byte 6 12) w))
                     (char out (+ o 2)) (if (< (+ i 1) n)
                                            (char +base64-alphabet+ (ldb (byte 6 6) w))
                                            #\=)
                     (char out (+ o 3)) (if (< (+ i 2) n)
                                            (char +base64-alphabet+ (ldb (byte 6 0) w))
                                            #\=))
               (incf o 4)))
    out))

(defun %b64-value (ch s)
  (let ((c (char-code ch)))
    (cond ((<= 65 c 90) (- c 65))
          ((<= 97 c 122) (- c 71))
          ((<= 48 c 57) (+ c 4))
          ((= c 43) 62)
          ((= c 47) 63)
          (t (error 'base64-error :string s)))))

(defun base64->octets (s)
  (let ((len (length s)))
    (unless (zerop (mod len 4)) (error 'base64-error :string s))
    (when (zerop len) (return-from base64->octets (make-octets 0)))
    (let* ((pad (cond ((and (char= (char s (- len 1)) #\=) (char= (char s (- len 2)) #\=)) 2)
                      ((char= (char s (- len 1)) #\=) 1)
                      (t 0)))
           (out (make-octets (- (* 3 (/ len 4)) pad)))
           (o 0))
      (loop for i from 0 below len by 4
            for last = (= i (- len 4))
            do (let* ((v0 (%b64-value (char s i) s))
                      (v1 (%b64-value (char s (+ i 1)) s))
                      (v2 (if (and last (>= pad 2)) 0 (%b64-value (char s (+ i 2)) s)))
                      (v3 (if (and last (>= pad 1)) 0 (%b64-value (char s (+ i 3)) s)))
                      (w (logior (ash v0 18) (ash v1 12) (ash v2 6) v3)))
                 ;; canonical: bits that padding discards must be zero
                 (when (and last (or (and (= pad 2) (/= 0 (ldb (byte 16 0) w)))
                                     (and (= pad 1) (/= 0 (ldb (byte 8 0) w)))))
                   (error 'base64-error :string s))
                 (setf (aref out o) (ldb (byte 8 16) w))
                 (when (< (+ o 1) (length out)) (setf (aref out (+ o 1)) (ldb (byte 8 8) w)))
                 (when (< (+ o 2) (length out)) (setf (aref out (+ o 2)) (ldb (byte 8 0) w)))
                 (incf o 3)))
      out)))

;;; ---------------------------------------------------------------------------
;;; Bech32 (BIP-173) — NIP-19 npub / nsec / note

(define-condition bech32-error (error)
  ((message :initarg :message :reader bech32-error-message))
  (:report (lambda (c s) (format s "bech32: ~A" (bech32-error-message c)))))

(defparameter +bech32-charset+ "qpzry9x8gf2tvdw0s3jn54khce6mua7l")

(defun %bech32-polymod (values)
  (let ((gen #(#x3b6a57b2 #x26508e6d #x1ea119fa #x3d4233dd #x2a1462b3))
        (chk 1))
    (dolist (v values chk)
      (let ((b (ash chk -25)))
        (setf chk (logxor (ash (logand chk #x1ffffff) 5) v))
        (dotimes (i 5)
          (when (logbitp i b) (setf chk (logxor chk (aref gen i)))))))))

(defun %bech32-hrp-expand (hrp)
  (append (map 'list (lambda (c) (ash (char-code c) -5)) hrp)
          (list 0)
          (map 'list (lambda (c) (logand (char-code c) 31)) hrp)))

(defun %convert-bits (data from to pad)
  (let ((acc 0) (bits 0) (out '()) (maxv (1- (ash 1 to))))
    (loop for v across data
          do (setf acc (logior (ash acc from) v))
             (incf bits from)
             (loop while (>= bits to)
                   do (decf bits to)
                      (push (logand (ash acc (- bits)) maxv) out)))
    (cond (pad (when (> bits 0) (push (logand (ash acc (- to bits)) maxv) out)))
          ((or (>= bits from) (/= 0 (logand (ash acc (- to bits)) maxv)))
           (error 'bech32-error :message "non-zero padding")))
    (coerce (nreverse out) 'vector)))

(defun bech32-encode (hrp octets)
  (let* ((data (coerce (%convert-bits octets 8 5 t) 'list))
         (poly (logxor 1 (%bech32-polymod (append (%bech32-hrp-expand hrp) data
                                                  (list 0 0 0 0 0 0)))))
         (checksum (loop for i from 0 below 6
                         collect (logand (ash poly (- (* 5 (- 5 i)))) 31))))
    (with-output-to-string (s)
      (write-string hrp s)
      (write-char #\1 s)
      (dolist (d (append data checksum))
        (write-char (char +bech32-charset+ d) s)))))

(defun bech32-decode (string)
  "Returns (values hrp octets).  Accepts all-lowercase or all-uppercase input."
  (when (and (string/= string (string-downcase string))
             (string/= string (string-upcase string)))
    (error 'bech32-error :message "mixed case"))
  (let* ((s (string-downcase string))
         (sep (position #\1 s :from-end t)))
    (unless (and sep (>= sep 1) (>= (- (length s) sep 1) 6))
      (error 'bech32-error :message "bad separator"))
    (let* ((hrp (subseq s 0 sep))
           (data (map 'list (lambda (c)
                              (or (position c +bech32-charset+)
                                  (error 'bech32-error :message "bad character")))
                      (subseq s (1+ sep)))))
      (unless (= 1 (%bech32-polymod (append (%bech32-hrp-expand hrp) data)))
        (error 'bech32-error :message "bad checksum"))
      (values hrp
              (coerce-octets (%convert-bits (coerce (butlast data 6) 'vector) 5 8 nil))))))

(defun npub-encode (pubkey32) (bech32-encode "npub" pubkey32))
(defun nsec-encode (seckey32) (bech32-encode "nsec" seckey32))

(defun npub-decode (string)
  (multiple-value-bind (hrp data) (bech32-decode string)
    (unless (and (string= hrp "npub") (= (length data) 32))
      (error 'bech32-error :message "not an npub"))
    data))

(defun nsec-decode (string)
  (multiple-value-bind (hrp data) (bech32-decode string)
    (unless (and (string= hrp "nsec") (= (length data) 32))
      (error 'bech32-error :message "not an nsec"))
    data))

(defun parse-pubkey (string)
  "Accept an npub or 64 lowercase hex characters."
  (if (and (> (length string) 4) (string= "npub" (string-downcase (subseq string 0 4))))
      (npub-decode string)
      (let ((v (hex->octets string)))
        (unless (= (length v) 32) (error 'hex-error :string string))
        v)))
