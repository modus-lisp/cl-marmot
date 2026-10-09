;;;; x25519.lisp — X25519 Diffie-Hellman (RFC 7748) and GF(2^255 - 19)
;;;;
;;;; Field elements are integers in [0, p).  Bignum multiplication is not
;;;; constant time and the ladder's conditional swap is a branch, so this is
;;;; best-effort only: the operation SEQUENCE is fixed (255 ladder steps,
;;;; independent of the scalar), but the underlying bignum timings are not.

(in-package #:cl-marmot)

(defconstant +p25519+ (- (expt 2 255) 19))

(declaim (inline f25519-reduce))
(defun f25519-reduce (x)
  "Reduce a non-negative X < 2^512 into [0, p) using 2^255 = 19 (mod p)."
  (let* ((m (1- (ash 1 255)))
         (r (+ (logand x m) (* 19 (ash x -255))))
         (r (+ (logand r m) (* 19 (ash r -255)))))
    (if (>= r +p25519+) (- r +p25519+) r)))

(defun f25519* (a b) (f25519-reduce (* a b)))
(defun f25519-sq (a) (f25519-reduce (* a a)))
(defun f25519+ (a b) (let ((r (+ a b))) (if (>= r +p25519+) (- r +p25519+) r)))
(defun f25519- (a b) (let ((r (- a b))) (if (minusp r) (+ r +p25519+) r)))
(defun f25519-inv (a) (mod-inverse a +p25519+))

(defun x25519-clamp (scalar)
  (let ((k (coerce-octets scalar)))
    (setf (aref k 0) (logand (aref k 0) 248)
          (aref k 31) (logior (logand (aref k 31) 127) 64))
    (octets->int-le k)))

(defun x25519-ladder (k u)
  "Montgomery ladder: x-coordinate of k*u (integers), RFC 7748 section 5."
  (let ((x1 u) (x2 1) (z2 0) (x3 u) (z3 1) (swap 0))
    (loop for i from 254 downto 0
          do (let ((bit (ldb (byte 1 i) k)))
               (setf swap (logxor swap bit))
               (when (= swap 1) (rotatef x2 x3) (rotatef z2 z3))
               (setf swap bit)
               (let* ((a (f25519+ x2 z2)) (aa (f25519-sq a))
                      (b (f25519- x2 z2)) (bb (f25519-sq b))
                      (e (f25519- aa bb))
                      (c (f25519+ x3 z3)) (d (f25519- x3 z3))
                      (da (f25519* d a)) (cb (f25519* c b)))
                 (setf x3 (f25519-sq (f25519+ da cb))
                       z3 (f25519* x1 (f25519-sq (f25519- da cb)))
                       x2 (f25519* aa bb)
                       z2 (f25519* e (f25519+ aa (f25519* 121665 e)))))))
    (when (= swap 1) (rotatef x2 x3) (rotatef z2 z3))
    (f25519* x2 (f25519-inv z2))))

(defun x25519 (scalar u)
  "X25519(scalar, u) per RFC 7748: 32 octets.  Signals CRYPTO-ERROR when the
result is all zero (a low-order input point)."
  (check-octets scalar 32 "x25519 scalar")
  (check-octets u 32 "x25519 u-coordinate")
  (let* ((ub (coerce-octets u)))
    (setf (aref ub 31) (logand (aref ub 31) 127))
    (let ((r (x25519-ladder (x25519-clamp scalar) (mod (octets->int-le ub) +p25519+))))
      (when (zerop r) (crypto-fail "x25519: all-zero shared secret"))
      (int->octets-le r 32))))

(defun x25519-base (scalar)
  "X25519 public key for the 32-octet private SCALAR (u = 9)."
  (check-octets scalar 32 "x25519 scalar")
  (int->octets-le (x25519-ladder (x25519-clamp scalar) 9) 32))
