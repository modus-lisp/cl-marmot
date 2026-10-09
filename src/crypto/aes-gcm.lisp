;;;; aes-gcm.lisp — AES (FIPS 197) and GCM (NIST SP 800-38D)
;;;;
;;;; AES uses the classic four 256-entry "T-tables", generated at load time.
;;;; Table lookups indexed by secret bytes are NOT constant time (cache
;;;; timing); the same is true of the bignum GHASH below.  Acceptable for a
;;;; client, noted here so nobody mistakes this for a hardened server AES.

(in-package #:cl-marmot)

(defun gf256-mul (a b)
  "Multiply in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1."
  (let ((p 0))
    (dotimes (i 8 p)
      (when (logbitp 0 b) (setf p (logxor p a)))
      (setf a (let ((x (ash a 1))) (if (logbitp 8 x) (logxor x #x11b) x))
            b (ash b -1)))))

(defun make-aes-sbox ()
  (let ((sbox (make-array 256 :element-type '(unsigned-byte 8))))
    (dotimes (x 256 sbox)
      (let ((inv (if (zerop x) 0 (loop for y from 1 below 256
                                       when (= 1 (gf256-mul x y)) return y)))
            (rotl8 (lambda (v n) (ldb (byte 8 0) (logior (ash v n) (ash v (- n 8)))))))
        (setf (aref sbox x)
              (logxor inv (funcall rotl8 inv 1) (funcall rotl8 inv 2)
                      (funcall rotl8 inv 3) (funcall rotl8 inv 4) #x63))))))

(declaim (type (simple-array (unsigned-byte 8) (256)) +aes-sbox+))
(defparameter +aes-sbox+ (make-aes-sbox))

(defun make-aes-te (rotation)
  (let ((te (make-array 256 :element-type '(unsigned-byte 32))))
    (dotimes (x 256 te)
      (let* ((s (aref +aes-sbox+ x))
             (w (logior (ash (gf256-mul s 2) 24) (ash s 16) (ash s 8) (gf256-mul s 3))))
        (setf (aref te x)
              (ldb (byte 32 0) (logior (ash w (- (* 8 rotation)))
                                       (ash w (- 32 (* 8 rotation))))))))))

(declaim (type (simple-array (unsigned-byte 32) (256)) +aes-te0+ +aes-te1+ +aes-te2+ +aes-te3+))
(defparameter +aes-te0+ (make-aes-te 0))
(defparameter +aes-te1+ (make-aes-te 1))
(defparameter +aes-te2+ (make-aes-te 2))
(defparameter +aes-te3+ (make-aes-te 3))

(defun aes-expand-key (key)
  "Round keys as a vector of 4*(rounds+1) big-endian 32-bit words."
  (let* ((nk (floor (length key) 4))
         (rounds (+ nk 6))
         (total (* 4 (1+ rounds)))
         (w (make-array total :element-type '(unsigned-byte 32)))
         (rcon 1))
    (unless (member (length key) '(16 24 32))
      (crypto-fail "AES key must be 16, 24 or 32 octets, got ~D" (length key)))
    (dotimes (i nk)
      (setf (aref w i) (octets->int-be key :start (* 4 i) :end (+ 4 (* 4 i)))))
    (flet ((sub-word (x)
             (logior (ash (aref +aes-sbox+ (ldb (byte 8 24) x)) 24)
                     (ash (aref +aes-sbox+ (ldb (byte 8 16) x)) 16)
                     (ash (aref +aes-sbox+ (ldb (byte 8 8) x)) 8)
                     (aref +aes-sbox+ (ldb (byte 8 0) x)))))
      (loop for i from nk below total
            do (let ((temp (aref w (1- i))))
                 (cond ((zerop (mod i nk))
                        (setf temp (logxor (sub-word (ldb (byte 32 0)
                                                          (logior (ash temp 8) (ash temp -24))))
                                           (ash rcon 24))
                              rcon (gf256-mul rcon 2)))
                       ((and (> nk 6) (= 4 (mod i nk)))
                        (setf temp (sub-word temp))))
                 (setf (aref w i) (logxor (aref w (- i nk)) temp)))))
    w))

(defun aes-encrypt-block (rk in in-off out out-off)
  "Encrypt the 16 octets of IN at IN-OFF into OUT at OUT-OFF."
  (declare (type (simple-array (unsigned-byte 32) (*)) rk)
           (type octets in out)
           (type fixnum in-off out-off)
           (optimize speed (safety 0)))
  (let ((te0 +aes-te0+) (te1 +aes-te1+) (te2 +aes-te2+) (te3 +aes-te3+)
        (sbox +aes-sbox+)
        (rounds (- (floor (length rk) 4) 1)))
    (declare (type fixnum rounds))
    (flet ((word (i)
             (declare (type fixnum i))
             (let ((j (+ in-off (* 4 i))))
               (logior (ash (aref in j) 24) (ash (aref in (+ j 1)) 16)
                       (ash (aref in (+ j 2)) 8) (aref in (+ j 3))))))
      (let ((s0 (logxor (word 0) (aref rk 0)))
            (s1 (logxor (word 1) (aref rk 1)))
            (s2 (logxor (word 2) (aref rk 2)))
            (s3 (logxor (word 3) (aref rk 3))))
        (declare (type u32 s0 s1 s2 s3))
        (loop for r of-type fixnum from 1 below rounds
              do (let ((k (* 4 r)))
                   (declare (type fixnum k))
                   (psetf s0 (logxor (aref te0 (ldb (byte 8 24) s0)) (aref te1 (ldb (byte 8 16) s1))
                                     (aref te2 (ldb (byte 8 8) s2)) (aref te3 (ldb (byte 8 0) s3))
                                     (aref rk k))
                          s1 (logxor (aref te0 (ldb (byte 8 24) s1)) (aref te1 (ldb (byte 8 16) s2))
                                     (aref te2 (ldb (byte 8 8) s3)) (aref te3 (ldb (byte 8 0) s0))
                                     (aref rk (+ k 1)))
                          s2 (logxor (aref te0 (ldb (byte 8 24) s2)) (aref te1 (ldb (byte 8 16) s3))
                                     (aref te2 (ldb (byte 8 8) s0)) (aref te3 (ldb (byte 8 0) s1))
                                     (aref rk (+ k 2)))
                          s3 (logxor (aref te0 (ldb (byte 8 24) s3)) (aref te1 (ldb (byte 8 16) s0))
                                     (aref te2 (ldb (byte 8 8) s1)) (aref te3 (ldb (byte 8 0) s2))
                                     (aref rk (+ k 3))))))
        (let ((k (* 4 rounds)))
          (flet ((final (a b c d key)
                   (declare (type u32 a b c d key))
                   (logxor (logior (ash (aref sbox (ldb (byte 8 24) a)) 24)
                                   (ash (aref sbox (ldb (byte 8 16) b)) 16)
                                   (ash (aref sbox (ldb (byte 8 8) c)) 8)
                                   (aref sbox (ldb (byte 8 0) d)))
                           key))
                 (put (i v)
                   (declare (type fixnum i) (type u32 v))
                   (let ((j (+ out-off (* 4 i))))
                     (setf (aref out j) (ldb (byte 8 24) v)
                           (aref out (+ j 1)) (ldb (byte 8 16) v)
                           (aref out (+ j 2)) (ldb (byte 8 8) v)
                           (aref out (+ j 3)) (ldb (byte 8 0) v)))))
            (put 0 (final s0 s1 s2 s3 (aref rk k)))
            (put 1 (final s1 s2 s3 s0 (aref rk (+ k 1))))
            (put 2 (final s2 s3 s0 s1 (aref rk (+ k 2))))
            (put 3 (final s3 s0 s1 s2 (aref rk (+ k 3))))))))
    out))

(defun aes-encrypt (key block)
  "Encrypt one 16-octet BLOCK under KEY (16/24/32 octets)."
  (check-octets block 16 "AES block")
  (aes-encrypt-block (aes-expand-key (ensure-octets key)) (ensure-octets block) 0
                     (make-octets 16) 0))

;;; GHASH.  Blocks are 128-bit integers read big-endian, so the first bit of
;;; the block is the coefficient of x^0 and "multiply by x" is a right shift.

(defconstant +gcm-r+ (ash #xe1 120))

(defun ghash-table (h)
  "P[i] = H * x^i for i = 0..127."
  (let ((p (make-array 128)))
    (dotimes (i 128 p)
      (setf (svref p i) h
            h (if (logbitp 0 h) (logxor (ash h -1) +gcm-r+) (ash h -1))))))

(defun ghash-mul (x table)
  (let ((z 0))
    (loop for i from 0 below 128
          when (logbitp (- 127 i) x)
            do (setf z (logxor z (svref table i))))
    z))

(defun ghash (table &rest parts)
  "GHASH over the concatenation of each part zero-padded to 16 octets."
  (let ((y 0))
    (dolist (part parts y)
      (let ((n (length part)))
        (loop for off from 0 below n by 16
              do (let* ((end (min n (+ off 16)))
                        (blk (ash (octets->int-be part :start off :end end)
                                  (* 8 (- 16 (- end off))))))
                   (setf y (ghash-mul (logxor y blk) table))))))))

(defun gcm-ctr (rk j0 data)
  "GCTR starting at inc32(J0)."
  (let* ((n (length data))
         (out (make-octets n))
         (ctr (copy-seq j0))
         (ks (make-octets 16))
         (count (octets->int-be j0 :start 12 :end 16)))
    (loop for off from 0 below n by 16
          do (setf count (ldb (byte 32 0) (1+ count)))
             (replace ctr (int->octets-be count 4) :start1 12)
             (aes-encrypt-block rk ctr 0 ks 0)
             (loop for i from 0 below (min 16 (- n off))
                   do (setf (aref out (+ off i)) (logxor (aref data (+ off i)) (aref ks i)))))
    out))

(defun gcm-setup (key nonce)
  "Round keys, GHASH table and J0 for KEY and NONCE."
  (let* ((key (ensure-octets key))
         (nonce (ensure-octets nonce))
         (rk (progn
               (unless (member (length key) '(16 32 24))
                 (crypto-fail "AES-GCM key must be 16 or 32 octets, got ~D" (length key)))
               (aes-expand-key key)))
         (h (octets->int-be (aes-encrypt-block rk (make-octets 16) 0 (make-octets 16) 0)))
         (table (ghash-table h))
         (j0 (if (= (length nonce) 12)
                 (concat-octets nonce (octets 0 0 0 1))
                 (progn
                   (when (zerop (length nonce)) (crypto-fail "AES-GCM: empty nonce"))
                   (int->octets-be (ghash table nonce
                                          (int->octets-be (* 8 (length nonce)) 16))
                                   16)))))
    (values rk table j0)))

(defun gcm-tag (rk table j0 aad ct)
  (let ((s (ghash table aad ct (concat-octets (int->octets-be (* 8 (length aad)) 8)
                                              (int->octets-be (* 8 (length ct)) 8))))
        (ej0 (aes-encrypt-block rk j0 0 (make-octets 16) 0)))
    (int->octets-be (logxor s (octets->int-be ej0)) 16)))

(defun aes-gcm-encrypt (key nonce plaintext aad)
  "AES-GCM seal (key 16 or 32 octets, 12-octet nonce): ciphertext || 16-octet tag."
  (multiple-value-bind (rk table j0) (gcm-setup key nonce)
    (let* ((aad (if aad (ensure-octets aad) (make-octets 0)))
           (ct (gcm-ctr rk j0 (ensure-octets plaintext))))
      (concat-octets ct (gcm-tag rk table j0 aad ct)))))

(defun aes-gcm-decrypt (key nonce ciphertext aad)
  "AES-GCM open of ciphertext || tag.  Signals AEAD-ERROR on a bad tag."
  (multiple-value-bind (rk table j0) (gcm-setup key nonce)
    (let* ((aad (if aad (ensure-octets aad) (make-octets 0)))
           (data (ensure-octets ciphertext))
           (n (length data)))
      (when (< n 16) (error 'aead-error :message "AES-GCM: input shorter than tag"))
      (let ((ct (subseq-octets data 0 (- n 16)))
            (tag (subseq-octets data (- n 16))))
        (unless (ct-octets= tag (gcm-tag rk table j0 aad ct))
          (error 'aead-error))
        (gcm-ctr rk j0 ct)))))
