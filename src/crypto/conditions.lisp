;;;; conditions.lisp — crypto conditions and the modular arithmetic the curves share

(in-package #:cl-marmot)

(define-condition crypto-error (error)
  ((message :initarg :message :initform "cryptographic failure"
            :reader crypto-error-message))
  (:report (lambda (c s) (format s "~A" (crypto-error-message c)))))

(define-condition aead-error (crypto-error)
  ()
  (:default-initargs :message "AEAD authentication failed"))

(defun crypto-fail (fmt &rest args)
  (error 'crypto-error :message (apply #'format nil fmt args)))

(defun check-octets (v len what)
  "Signal CRYPTO-ERROR unless V is an octet vector of length LEN (any length if NIL)."
  (unless (and (typep v '(vector (unsigned-byte 8)))
               (or (null len) (= (length v) len)))
    (crypto-fail "~A: expected ~@[~D-byte ~]octet vector" what len))
  v)

(defun ensure-octets (v)
  "Return V as a simple octet vector, copying only when it is not one already."
  (if (typep v 'octets) v (coerce-octets v)))

;;; Modular arithmetic on integers (bignums are fine for field math).
;;; NOT constant time: the running time of MOD-EXPT depends on the bits of
;;; the exponent and of bignum magnitudes.  Callers use it with public
;;; exponents (p-2, (p+1)/4, ...) only.

(defun mod-expt (base exponent modulus)
  "BASE^EXPONENT mod MODULUS by left-to-right square-and-multiply."
  (let ((result 1)
        (b (mod base modulus)))
    (loop for i from (1- (integer-length exponent)) downto 0
          do (setf result (mod (* result result) modulus))
             (when (logbitp i exponent)
               (setf result (mod (* result b) modulus))))
    (mod result modulus)))

(defun mod-inverse (a modulus)
  "Inverse of A modulo the prime MODULUS (extended Euclid); 0 maps to 0."
  (let ((a (mod a modulus)))
    (if (zerop a)
        0
        (let ((r0 modulus) (r1 a) (t0 0) (t1 1))
          (loop until (zerop r1)
                do (let ((q (floor r0 r1)))
                     (psetf r0 r1 r1 (- r0 (* q r1)))
                     (psetf t0 t1 t1 (- t0 (* q t1)))))
          (mod t0 modulus)))))
