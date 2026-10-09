;;;; secp256k1.lisp — secp256k1, BIP-340 Schnorr signatures and x-only ECDH
;;;;
;;;; Points are simple-vectors #(X Y Z) in Jacobian coordinates
;;;; (x = X/Z^2, y = Y/Z^3); Z = 0 is the point at infinity.  The addition
;;;; formulas are not complete, so ADD branches on the doubling and infinity
;;;; cases.  Fixed-base multiples use a lazily built k*16^j*G table.
;;;; Not constant time (bignums, branches, secret-indexed table reads).

(in-package #:cl-marmot)

(defconstant +secp-p+ (- (expt 2 256) (expt 2 32) 977))
(defconstant +secp-n+ #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
(defconstant +secp-gx+ #x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
(defconstant +secp-gy+ #x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

(declaim (inline fk-reduce))
(defun fk-reduce (x)
  "Reduce a non-negative X into [0, p) using 2^256 = 2^32 + 977 (mod p)."
  (let ((m (1- (ash 1 256)))
        (c (+ (ash 1 32) 977)))
    (loop while (> (integer-length x) 256)
          do (setf x (+ (logand x m) (* c (ash x -256)))))
    (if (>= x +secp-p+) (- x +secp-p+) x)))

(defun fk* (a b) (fk-reduce (* a b)))
(defun fk-sq (a) (fk-reduce (* a a)))
(defun fk+ (a b) (let ((r (+ a b))) (if (>= r +secp-p+) (- r +secp-p+) r)))
(defun fk- (a b) (let ((r (- a b))) (if (minusp r) (+ r +secp-p+) r)))
(defun fk-small* (k a) (fk-reduce (* k a)))

(defun secp-infinity () (vector 0 1 0))
(defun secp-infinity-p (p) (zerop (svref p 2)))

(defun secp-double (p)
  (let ((x1 (svref p 0)) (y1 (svref p 1)) (z1 (svref p 2)))
    (if (or (zerop z1) (zerop y1))
        (secp-infinity)
        (let* ((a (fk-sq x1))
               (b (fk-sq y1))
               (c (fk-sq b))
               (d (fk-small* 2 (fk- (fk- (fk-sq (fk+ x1 b)) a) c)))
               (e (fk-small* 3 a))
               (f (fk-sq e))
               (x3 (fk- f (fk+ d d)))
               (y3 (fk- (fk* e (fk- d x3)) (fk-small* 8 c)))
               (z3 (fk-small* 2 (fk* y1 z1))))
          (vector x3 y3 z3)))))

(defun secp-add (p q)
  (cond ((secp-infinity-p p) q)
        ((secp-infinity-p q) p)
        (t
         (let* ((x1 (svref p 0)) (y1 (svref p 1)) (z1 (svref p 2))
                (x2 (svref q 0)) (y2 (svref q 1)) (z2 (svref q 2))
                (z1z1 (fk-sq z1)) (z2z2 (fk-sq z2))
                (u1 (fk* x1 z2z2)) (u2 (fk* x2 z1z1))
                (s1 (fk* (fk* y1 z2) z2z2)) (s2 (fk* (fk* y2 z1) z1z1))
                (h (fk- u2 u1))
                (r (fk-small* 2 (fk- s2 s1))))
           (if (zerop h)
               (if (zerop r) (secp-double p) (secp-infinity))
               (let* ((i (fk-sq (fk+ h h)))
                      (j (fk* h i))
                      (v (fk* u1 i))
                      (x3 (fk- (fk- (fk-sq r) j) (fk+ v v)))
                      (y3 (fk- (fk* r (fk- v x3)) (fk-small* 2 (fk* s1 j))))
                      (z3 (fk* (fk- (fk- (fk-sq (fk+ z1 z2)) z1z1) z2z2) h)))
                 (vector x3 y3 z3)))))))

(defun secp-affine (p)
  "Affine (x, y) of a finite point as two values."
  (let* ((zi (mod-inverse (svref p 2) +secp-p+))
         (zi2 (fk-sq zi)))
    (values (fk* (svref p 0) zi2) (fk* (svref p 1) (fk* zi2 zi)))))

(defvar *secp-base-table* nil
  "Vector of 64 vectors: entry [j][k] is k * 16^j * G.")

(defun secp-base-table ()
  (or *secp-base-table*
      (setf *secp-base-table*
            (let ((tables (make-array 64))
                  (base (vector +secp-gx+ +secp-gy+ 1)))
              (dotimes (j 64 tables)
                (let ((row (make-array 16)))
                  (setf (svref row 0) (secp-infinity))
                  (loop for k from 1 below 16
                        do (setf (svref row k) (secp-add (svref row (1- k)) base)))
                  ;; Normalise to Z = 1 so table entries are cheap to add.
                  (loop for k from 1 below 16
                        do (multiple-value-bind (x y) (secp-affine (svref row k))
                             (setf (svref row k) (vector x y 1))))
                  (setf (svref tables j) row
                        base (secp-double (secp-double (secp-double (secp-double base)))))))))))

(defun secp-base-mul (k)
  "k*G for 0 <= k < 2^256."
  (let ((table (secp-base-table))
        (acc (secp-infinity)))
    (dotimes (j 64 acc)
      (setf acc (secp-add acc (svref (svref table j) (ldb (byte 4 (* 4 j)) k)))))))

(defun secp-mul (k p)
  "k*P for 0 <= k < 2^256, 4-bit fixed window."
  (let ((multiples (make-array 16))
        (acc (secp-infinity)))
    (setf (svref multiples 0) (secp-infinity))
    (loop for i from 1 below 16
          do (setf (svref multiples i) (secp-add (svref multiples (1- i)) p)))
    (loop for j from 63 downto 0
          do (setf acc (secp-double (secp-double (secp-double (secp-double acc)))))
             (setf acc (secp-add acc (svref multiples (ldb (byte 4 (* 4 j)) k)))))
    acc))

(defun secp-lift-x (x)
  "The point with x-coordinate X and even y (BIP-340 lift_x), or NIL."
  (when (< x +secp-p+)
    (let* ((c (fk+ (fk* (fk-sq x) x) 7))
           (y (mod-expt c (/ (+ +secp-p+ 1) 4) +secp-p+)))
      (when (= (fk-sq y) c)
        (vector x (if (evenp y) y (- +secp-p+ y)) 1)))))

(defun octets-32-p (v)
  (and (typep v '(vector (unsigned-byte 8))) (= (length v) 32)))

;;; Public API

(defun secp256k1-valid-seckey-p (sk)
  "True iff SK is 32 octets encoding an integer in [1, n-1]."
  (and (octets-32-p sk)
       (< 0 (octets->int-be sk) +secp-n+)))

(defun secp256k1-valid-xonly-p (pk)
  "True iff PK is a 32-octet x-only public key: x < p and lift_x(x) exists."
  (and (octets-32-p pk)
       (secp-lift-x (octets->int-be pk))
       t))

(defun secp256k1-xonly-pubkey (sk)
  "The 32-octet x-only (BIP-340) public key of secret key SK."
  (unless (secp256k1-valid-seckey-p sk) (crypto-fail "secp256k1: invalid secret key"))
  (int->octets-be (secp-affine (secp-base-mul (octets->int-be sk))) 32))

(defun tagged-hash (tag &rest parts)
  "BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || parts...)."
  (let ((th (sha256 (string->utf8 tag))))
    (sha256 (apply #'concat-octets th th parts))))

(defun bip340-sign (sk msg &optional aux)
  "BIP-340 Schnorr signature (64 octets) of MSG under the 32-octet secret key SK.
AUX is 32 octets of auxiliary randomness, fresh from the OS by default."
  (unless (secp256k1-valid-seckey-p sk) (crypto-fail "bip340-sign: invalid secret key"))
  (let* ((msg (ensure-octets msg))
         (aux (if aux (check-octets aux 32 "bip340 aux") (random-octets 32)))
         (d0 (octets->int-be sk)))
    (multiple-value-bind (px py) (secp-affine (secp-base-mul d0))
      (let* ((d (if (evenp py) d0 (- +secp-n+ d0)))
             (pb (int->octets-be px 32))
             (tv (int->octets-be (logxor d (octets->int-be (tagged-hash "BIP0340/aux" aux))) 32))
             (k0 (mod (octets->int-be (tagged-hash "BIP0340/nonce" tv pb msg)) +secp-n+)))
        (when (zerop k0) (crypto-fail "bip340-sign: nonce is zero"))
        (multiple-value-bind (rx ry) (secp-affine (secp-base-mul k0))
          (let* ((k (if (evenp ry) k0 (- +secp-n+ k0)))
                 (rb (int->octets-be rx 32))
                 (e (mod (octets->int-be (tagged-hash "BIP0340/challenge" rb pb msg)) +secp-n+))
                 (sig (concat-octets rb (int->octets-be (mod (+ k (* e d)) +secp-n+) 32))))
            (unless (bip340-verify pb msg sig)
              (crypto-fail "bip340-sign: produced signature does not verify"))
            sig))))))

(defun bip340-verify (pk msg sig)
  "True iff SIG is a valid BIP-340 signature of MSG under the x-only key PK.
Never signals: malformed inputs simply fail verification."
  (handler-case
      (and (octets-32-p pk)
           (typep msg '(vector (unsigned-byte 8)))
           (typep sig '(vector (unsigned-byte 8))) (= (length sig) 64)
           (let ((p (secp-lift-x (octets->int-be pk)))
                 (r (octets->int-be sig :start 0 :end 32))
                 (s (octets->int-be sig :start 32 :end 64)))
             (and p (< r +secp-p+) (< s +secp-n+)
                  (let* ((e (mod (octets->int-be
                                  (tagged-hash "BIP0340/challenge"
                                               (subseq-octets sig 0 32)
                                               (ensure-octets pk) (ensure-octets msg)))
                                 +secp-n+))
                         (rr (secp-add (secp-base-mul s) (secp-mul (mod (- +secp-n+ e) +secp-n+) p))))
                    (and (not (secp-infinity-p rr))
                         (multiple-value-bind (x y) (secp-affine rr)
                           (and (evenp y) (= x r))))))))
    (error () nil)))

(defun secp256k1-ecdh-x (sk pk)
  "The 32-octet x-coordinate of SK * lift_x(PK), unhashed (NIP-44 v2's shared_x)."
  (unless (secp256k1-valid-seckey-p sk) (crypto-fail "secp256k1-ecdh-x: invalid secret key"))
  (let ((p (and (octets-32-p pk) (secp-lift-x (octets->int-be pk)))))
    (unless p (crypto-fail "secp256k1-ecdh-x: invalid x-only public key"))
    (let ((q (secp-mul (octets->int-be sk) p)))
      (when (secp-infinity-p q) (crypto-fail "secp256k1-ecdh-x: result is infinity"))
      (int->octets-be (secp-affine q) 32))))
