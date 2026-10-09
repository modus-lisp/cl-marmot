;;;; ed25519.lisp — Ed25519 signatures (RFC 8032, pure Ed25519)
;;;;
;;;; Points are simple-vectors #(X Y Z T) in extended twisted-Edwards
;;;; coordinates (x = X/Z, y = Y/Z, xy = T/Z), using the complete addition
;;;; and doubling formulas of RFC 8032 section 5.1.4.  Fixed-base multiples
;;;; come from a lazily built table of k*16^j*B (64 x 16 points), so a
;;;; signature costs 64 point additions.  Not constant time: field elements
;;;; are bignums and table indices are secret nibbles (see x25519.lisp).

(in-package #:cl-marmot)

(defconstant +ed25519-l+
  (+ (expt 2 252) 27742317777372353535851937790883648493))

(defparameter +ed25519-d+
  (mod (* -121665 (mod-inverse 121666 +p25519+)) +p25519+))
(defparameter +ed25519-2d+ (mod (* 2 +ed25519-d+) +p25519+))
(defparameter +ed25519-sqrt-m1+
  (mod-expt 2 (/ (- +p25519+ 1) 4) +p25519+))

(defparameter +ed25519-base+
  (let ((x 15112221349535400772501151409588531511454012693041857206046113283949847762202)
        (y 46316835694926478169428394003475163141307993866256225615783033603165251855960))
    (vector x y 1 (f25519* x y))))

(defun ed-identity () (vector 0 1 1 0))

(defun ed-add (p q)
  (let* ((x1 (svref p 0)) (y1 (svref p 1)) (z1 (svref p 2)) (t1 (svref p 3))
         (x2 (svref q 0)) (y2 (svref q 1)) (z2 (svref q 2)) (t2 (svref q 3))
         (a (f25519* (f25519- y1 x1) (f25519- y2 x2)))
         (b (f25519* (f25519+ y1 x1) (f25519+ y2 x2)))
         (c (f25519* (f25519* t1 +ed25519-2d+) t2))
         (d (f25519* (f25519+ z1 z1) z2))
         (e (f25519- b a)) (f (f25519- d c)) (g (f25519+ d c)) (h (f25519+ b a)))
    (vector (f25519* e f) (f25519* g h) (f25519* f g) (f25519* e h))))

(defun ed-double (p)
  (let* ((x1 (svref p 0)) (y1 (svref p 1)) (z1 (svref p 2))
         (a (f25519-sq x1))
         (b (f25519-sq y1))
         (c (let ((zz (f25519-sq z1))) (f25519+ zz zz)))
         (h (f25519+ a b))
         (e (f25519- h (f25519-sq (f25519+ x1 y1))))
         (g (f25519- a b))
         (f (f25519+ c g)))
    (vector (f25519* e f) (f25519* g h) (f25519* f g) (f25519* e h))))

(defun ed-negate (p)
  (vector (f25519- 0 (svref p 0)) (svref p 1) (svref p 2) (f25519- 0 (svref p 3))))

(defun ed-encode (p)
  (let* ((zi (f25519-inv (svref p 2)))
         (x (f25519* (svref p 0) zi))
         (y (f25519* (svref p 1) zi)))
    (int->octets-le (logior y (ash (logand x 1) 255)) 32)))

(defun ed-decode (bytes)
  "Decode a 32-octet point (RFC 8032 5.1.3); NIL if it is not a valid encoding."
  (let* ((n (octets->int-le bytes))
         (x0 (ldb (byte 1 255) n))
         (y (ldb (byte 255 0) n)))
    (when (>= y +p25519+) (return-from ed-decode nil))
    (let* ((yy (f25519-sq y))
           (u (f25519- yy 1))
           (v (f25519+ (f25519* +ed25519-d+ yy) 1))
           (v3 (f25519* (f25519-sq v) v))
           (x (f25519* (f25519* u v3)
                       (mod-expt (f25519* u (f25519* v3 (f25519* v3 v)))
                                 (/ (- +p25519+ 5) 8) +p25519+)))
           (vxx (f25519* v (f25519-sq x))))
      (cond ((= vxx u))
            ((= vxx (f25519- 0 u)) (setf x (f25519* x +ed25519-sqrt-m1+)))
            (t (return-from ed-decode nil)))
      (when (and (zerop x) (= x0 1)) (return-from ed-decode nil))
      (unless (= (logand x 1) x0) (setf x (f25519- 0 x)))
      (vector x y 1 (f25519* x y)))))

(defvar *ed25519-base-table* nil
  "Vector of 64 vectors: entry [j][k] is k * 16^j * B.")

(defun ed25519-base-table ()
  (or *ed25519-base-table*
      (setf *ed25519-base-table*
            (let ((tables (make-array 64))
                  (base +ed25519-base+))
              (dotimes (j 64 tables)
                (let ((row (make-array 16)))
                  (setf (svref row 0) (ed-identity))
                  (loop for k from 1 below 16
                        do (setf (svref row k) (ed-add (svref row (1- k)) base)))
                  (setf (svref tables j) row
                        base (ed-double (ed-double (ed-double (ed-double base)))))))))))

(defun ed-base-mul (s)
  "s*B for 0 <= s < 2^256 using the fixed-base table (64 additions)."
  (let ((table (ed25519-base-table))
        (acc (ed-identity)))
    (dotimes (j 64 acc)
      (setf acc (ed-add acc (svref (svref table j) (ldb (byte 4 (* 4 j)) s)))))))

(defun ed-mul (s p)
  "s*P for 0 <= s < 2^256, 4-bit fixed window."
  (let ((multiples (make-array 16))
        (acc (ed-identity)))
    (setf (svref multiples 0) (ed-identity))
    (loop for k from 1 below 16
          do (setf (svref multiples k) (ed-add (svref multiples (1- k)) p)))
    (loop for j from 63 downto 0
          do (setf acc (ed-double (ed-double (ed-double (ed-double acc)))))
             (setf acc (ed-add acc (svref multiples (ldb (byte 4 (* 4 j)) s)))))
    acc))

(defun ed25519-expand (seed)
  "Secret scalar and nonce prefix from the 32-octet SEED."
  (check-octets seed 32 "ed25519 seed")
  (let* ((h (sha512 seed))
         (a (subseq-octets h 0 32)))
    (setf (aref a 0) (logand (aref a 0) 248)
          (aref a 31) (logior (logand (aref a 31) 127) 64))
    (values (octets->int-le a) (subseq-octets h 32 64))))

(defun ed25519-public-key (seed)
  "The 32-octet Ed25519 public key for a 32-octet private SEED."
  (ed-encode (ed-base-mul (ed25519-expand seed))))

(defun ed25519-sign (seed message)
  "64-octet Ed25519 signature R || S over MESSAGE."
  (let ((message (ensure-octets message)))
    (multiple-value-bind (a prefix) (ed25519-expand seed)
      (let* ((pub (ed-encode (ed-base-mul a)))
             (r (mod (octets->int-le (sha512 (concat-octets prefix message))) +ed25519-l+))
             (rb (ed-encode (ed-base-mul r)))
             (k (mod (octets->int-le (sha512 (concat-octets rb pub message))) +ed25519-l+))
             (s (mod (+ r (* k a)) +ed25519-l+)))
        (concat-octets rb (int->octets-le s 32))))))

(defun ed25519-verify (public message signature)
  "True iff SIGNATURE is a valid Ed25519 signature of MESSAGE under PUBLIC.
Never signals: malformed inputs simply fail verification."
  (handler-case
      (and (typep public '(vector (unsigned-byte 8))) (= (length public) 32)
           (typep signature '(vector (unsigned-byte 8))) (= (length signature) 64)
           (typep message '(vector (unsigned-byte 8)))
           (let* ((public (ensure-octets public))
                  (signature (ensure-octets signature))
                  (message (ensure-octets message))
                  (a (ed-decode public))
                  (rb (subseq-octets signature 0 32))
                  (s (octets->int-le signature :start 32 :end 64)))
             (and a
                  (< s +ed25519-l+)
                  (let* ((k (mod (octets->int-le (sha512 (concat-octets rb public message)))
                                 +ed25519-l+))
                         (check (ed-add (ed-base-mul s) (ed-mul k (ed-negate a)))))
                    (octets= (ed-encode check) rb))
                  t)))
    (error () nil)))
