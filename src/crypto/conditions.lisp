;;;; conditions.lisp — crypto conditions

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
