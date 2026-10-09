;;;; sha2.lisp — SHA-256, SHA-384 and SHA-512 (FIPS 180-4)
;;;;
;;;; One-shot digests over octet vectors.  Full blocks are compressed straight
;;;; out of the input; only the final one or two padded blocks are copied.
;;;;
;;;; SHA-256 works on 32-bit words held in fixnums, written as
;;;; (ldb (byte 32 0) ...), which every 64-bit Lisp keeps unboxed.  SHA-512
;;;; needs 64-bit words: SBCL does that modular arithmetic natively; a Lisp
;;;; with 62/63-bit fixnums (Modus) computes the same values with bignums,
;;;; correctly but more slowly.

(in-package #:cl-marmot)

(deftype u32 () '(unsigned-byte 32))
(deftype u64 () '(unsigned-byte 64))

(defmacro u32+ (&rest xs) `(ldb (byte 32 0) (+ ,@xs)))
(defmacro rotr32 (x n)
  `(logior (ash ,x ,(- n)) (ldb (byte 32 0) (ash ,x ,(- 32 n)))))
(defmacro u64+ (&rest xs) `(ldb (byte 64 0) (+ ,@xs)))
(defmacro rotr64 (x n)
  `(logior (ash ,x ,(- n)) (ldb (byte 64 0) (ash ,x ,(- 64 n)))))

;;; ------------------------------------------------------------------ SHA-256

(declaim (type (simple-array (unsigned-byte 32) (64)) +sha256-k+))
(defparameter +sha256-k+
  (make-array 64 :element-type '(unsigned-byte 32) :initial-contents
   '(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
     #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
     #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
     #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
     #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
     #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
     #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
     #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)))

(defun sha256-compress (state buf offset w)
  (declare (type (simple-array (unsigned-byte 32) (8)) state)
           (type octets buf)
           (type (simple-array (unsigned-byte 32) (64)) w)
           (type fixnum offset)
           (optimize speed (safety 0)))
  (let ((k +sha256-k+))
    (dotimes (i 16)
      (let ((j (+ offset (* 4 i))))
        (declare (type fixnum j))
        (setf (aref w i) (logior (ash (aref buf j) 24) (ash (aref buf (+ j 1)) 16)
                                 (ash (aref buf (+ j 2)) 8) (aref buf (+ j 3))))))
    (loop for i of-type fixnum from 16 below 64
          do (let* ((x (aref w (- i 15)))
                    (y (aref w (- i 2)))
                    (s0 (logxor (rotr32 x 7) (rotr32 x 18) (ash x -3)))
                    (s1 (logxor (rotr32 y 17) (rotr32 y 19) (ash y -10))))
               (declare (type u32 x y s0 s1))
               (setf (aref w i) (u32+ (aref w (- i 16)) s0 (aref w (- i 7)) s1))))
    (let ((a (aref state 0)) (b (aref state 1)) (c (aref state 2)) (d (aref state 3))
          (e (aref state 4)) (f (aref state 5)) (g (aref state 6)) (h (aref state 7)))
      (declare (type u32 a b c d e f g h))
      (dotimes (i 64)
        (let* ((s1 (logxor (rotr32 e 6) (rotr32 e 11) (rotr32 e 25)))
               (ch (logxor (logand e f) (logand (logxor e #xFFFFFFFF) g)))
               (t1 (u32+ h s1 ch (aref k i) (aref w i)))
               (s0 (logxor (rotr32 a 2) (rotr32 a 13) (rotr32 a 22)))
               (maj (logxor (logand a b) (logand a c) (logand b c)))
               (t2 (u32+ s0 maj)))
          (declare (type u32 s1 ch t1 s0 maj t2))
          (setf h g g f f e e (u32+ d t1) d c c b b a a (u32+ t1 t2))))
      (setf (aref state 0) (u32+ (aref state 0) a) (aref state 1) (u32+ (aref state 1) b)
            (aref state 2) (u32+ (aref state 2) c) (aref state 3) (u32+ (aref state 3) d)
            (aref state 4) (u32+ (aref state 4) e) (aref state 5) (u32+ (aref state 5) f)
            (aref state 6) (u32+ (aref state 6) g) (aref state 7) (u32+ (aref state 7) h))))
  state)

(defun md-tail (data block-size length-bytes)
  "The padded final block(s) of a Merkle-Damgard hash over DATA: the trailing
partial block, #x80, zeros, and the big-endian bit length in LENGTH-BYTES."
  (let* ((n (length data))
         (rem (mod n block-size))
         (tail-len (if (< rem (- block-size length-bytes)) block-size (* 2 block-size)))
         (tail (make-octets tail-len)))
    (replace tail data :start2 (- n rem))
    (setf (aref tail rem) #x80)
    (let ((bits (* 8 n)))
      (dotimes (i length-bytes)
        (setf (aref tail (- tail-len 1 i)) (ldb (byte 8 (* 8 i)) bits))))
    tail))

(defun sha256 (data)
  "SHA-256 digest (32 octets) of the octet vector DATA."
  (let* ((data (ensure-octets data))
         (state (make-array 8 :element-type '(unsigned-byte 32)
                              :initial-contents '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                                                  #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)))
         (w (make-array 64 :element-type '(unsigned-byte 32)))
         (full (* 64 (floor (length data) 64)))
         (tail (md-tail data 64 8)))
    (loop for off from 0 below full by 64 do (sha256-compress state data off w))
    (loop for off from 0 below (length tail) by 64 do (sha256-compress state tail off w))
    (let ((out (make-octets 32)))
      (dotimes (i 8 out)
        (dotimes (j 4)
          (setf (aref out (+ (* 4 i) j)) (ldb (byte 8 (- 24 (* 8 j))) (aref state i))))))))

;;; ------------------------------------------------------------------ SHA-512

(declaim (type (simple-array (unsigned-byte 64) (80)) +sha512-k+))
(defparameter +sha512-k+
  (make-array 80 :element-type '(unsigned-byte 64) :initial-contents
   '(#x428a2f98d728ae22 #x7137449123ef65cd #xb5c0fbcfec4d3b2f #xe9b5dba58189dbbc
     #x3956c25bf348b538 #x59f111f1b605d019 #x923f82a4af194f9b #xab1c5ed5da6d8118
     #xd807aa98a3030242 #x12835b0145706fbe #x243185be4ee4b28c #x550c7dc3d5ffb4e2
     #x72be5d74f27b896f #x80deb1fe3b1696b1 #x9bdc06a725c71235 #xc19bf174cf692694
     #xe49b69c19ef14ad2 #xefbe4786384f25e3 #x0fc19dc68b8cd5b5 #x240ca1cc77ac9c65
     #x2de92c6f592b0275 #x4a7484aa6ea6e483 #x5cb0a9dcbd41fbd4 #x76f988da831153b5
     #x983e5152ee66dfab #xa831c66d2db43210 #xb00327c898fb213f #xbf597fc7beef0ee4
     #xc6e00bf33da88fc2 #xd5a79147930aa725 #x06ca6351e003826f #x142929670a0e6e70
     #x27b70a8546d22ffc #x2e1b21385c26c926 #x4d2c6dfc5ac42aed #x53380d139d95b3df
     #x650a73548baf63de #x766a0abb3c77b2a8 #x81c2c92e47edaee6 #x92722c851482353b
     #xa2bfe8a14cf10364 #xa81a664bbc423001 #xc24b8b70d0f89791 #xc76c51a30654be30
     #xd192e819d6ef5218 #xd69906245565a910 #xf40e35855771202a #x106aa07032bbd1b8
     #x19a4c116b8d2d0c8 #x1e376c085141ab53 #x2748774cdf8eeb99 #x34b0bcb5e19b48a8
     #x391c0cb3c5c95a63 #x4ed8aa4ae3418acb #x5b9cca4f7763e373 #x682e6ff3d6b2b8a3
     #x748f82ee5defb2fc #x78a5636f43172f60 #x84c87814a1f0ab72 #x8cc702081a6439ec
     #x90befffa23631e28 #xa4506cebde82bde9 #xbef9a3f7b2c67915 #xc67178f2e372532b
     #xca273eceea26619c #xd186b8c721c0c207 #xeada7dd6cde0eb1e #xf57d4f7fee6ed178
     #x06f067aa72176fba #x0a637dc5a2c898a6 #x113f9804bef90dae #x1b710b35131c471b
     #x28db77f523047d84 #x32caab7b40c72493 #x3c9ebe0a15c9bebc #x431d67c49c100d4c
     #x4cc5d4becb3e42b6 #x597f299cfc657e2a #x5fcb6fab3ad6faec #x6c44198c4a475817)))

(defun sha512-compress (state buf offset w)
  (declare (type (simple-array (unsigned-byte 64) (8)) state)
           (type octets buf)
           (type (simple-array (unsigned-byte 64) (80)) w)
           (type fixnum offset)
           (optimize speed (safety 0)))
  (let ((k +sha512-k+))
    (dotimes (i 16)
      (let ((j (+ offset (* 8 i)))
            (v 0))
        (declare (type fixnum j) (type u64 v))
        (dotimes (m 8)
          (setf v (logior (ldb (byte 64 0) (ash v 8)) (aref buf (+ j m)))))
        (setf (aref w i) v)))
    (loop for i of-type fixnum from 16 below 80
          do (let* ((x (aref w (- i 15)))
                    (y (aref w (- i 2)))
                    (s0 (logxor (rotr64 x 1) (rotr64 x 8) (ash x -7)))
                    (s1 (logxor (rotr64 y 19) (rotr64 y 61) (ash y -6))))
               (declare (type u64 x y s0 s1))
               (setf (aref w i) (u64+ (aref w (- i 16)) s0 (aref w (- i 7)) s1))))
    (let ((a (aref state 0)) (b (aref state 1)) (c (aref state 2)) (d (aref state 3))
          (e (aref state 4)) (f (aref state 5)) (g (aref state 6)) (h (aref state 7)))
      (declare (type u64 a b c d e f g h))
      (dotimes (i 80)
        (let* ((s1 (logxor (rotr64 e 14) (rotr64 e 18) (rotr64 e 41)))
               (ch (logxor (logand e f) (logand (logxor e #xFFFFFFFFFFFFFFFF) g)))
               (t1 (u64+ h s1 ch (aref k i) (aref w i)))
               (s0 (logxor (rotr64 a 28) (rotr64 a 34) (rotr64 a 39)))
               (maj (logxor (logand a b) (logand a c) (logand b c)))
               (t2 (u64+ s0 maj)))
          (declare (type u64 s1 ch t1 s0 maj t2))
          (setf h g g f f e e (u64+ d t1) d c c b b a a (u64+ t1 t2))))
      (setf (aref state 0) (u64+ (aref state 0) a) (aref state 1) (u64+ (aref state 1) b)
            (aref state 2) (u64+ (aref state 2) c) (aref state 3) (u64+ (aref state 3) d)
            (aref state 4) (u64+ (aref state 4) e) (aref state 5) (u64+ (aref state 5) f)
            (aref state 6) (u64+ (aref state 6) g) (aref state 7) (u64+ (aref state 7) h))))
  state)

(defun sha512-family (data iv out-len)
  (let* ((data (ensure-octets data))
         (state (make-array 8 :element-type '(unsigned-byte 64) :initial-contents iv))
         (w (make-array 80 :element-type '(unsigned-byte 64)))
         (full (* 128 (floor (length data) 128)))
         (tail (md-tail data 128 16)))
    (loop for off from 0 below full by 128 do (sha512-compress state data off w))
    (loop for off from 0 below (length tail) by 128 do (sha512-compress state tail off w))
    (let ((out (make-octets out-len)))
      (dotimes (i out-len out)
        (setf (aref out i)
              (ldb (byte 8 (- 56 (* 8 (mod i 8)))) (aref state (floor i 8))))))))

(defun sha512 (data)
  "SHA-512 digest (64 octets) of the octet vector DATA."
  (sha512-family data '(#x6a09e667f3bcc908 #xbb67ae8584caa73b #x3c6ef372fe94f82b
                        #xa54ff53a5f1d36f1 #x510e527fade682d1 #x9b05688c2b3e6c1f
                        #x1f83d9abfb41bd6b #x5be0cd19137e2179)
                 64))

(defun sha384 (data)
  "SHA-384 digest (48 octets) of the octet vector DATA."
  (sha512-family data '(#xcbbb9d5dc1059ed8 #x629a292a367cd507 #x9159015a3070dd17
                        #x152fecd8f70e5939 #x67332667ffc00b31 #x8eb44a8768581511
                        #xdb0c2e0d64f98fa7 #x47b5481dbefa4fa4)
                 48))
