;;;; base64.lisp — RFC 4648 §4 base64 (standard alphabet, padded)
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
