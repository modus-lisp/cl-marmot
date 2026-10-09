;;;; chacha20.lisp — ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (RFC 8439)

(in-package #:cl-marmot)

(defmacro rotl32 (x n)
  `(logior (ldb (byte 32 0) (ash ,x ,n)) (ash ,x ,(- n 32))))

(defmacro chacha-quarter-round (x a b c d)
  `(progn
     (setf (aref ,x ,a) (u32+ (aref ,x ,a) (aref ,x ,b))
           (aref ,x ,d) (let ((v (logxor (aref ,x ,d) (aref ,x ,a))))
                          (declare (type u32 v)) (rotl32 v 16)))
     (setf (aref ,x ,c) (u32+ (aref ,x ,c) (aref ,x ,d))
           (aref ,x ,b) (let ((v (logxor (aref ,x ,b) (aref ,x ,c))))
                          (declare (type u32 v)) (rotl32 v 12)))
     (setf (aref ,x ,a) (u32+ (aref ,x ,a) (aref ,x ,b))
           (aref ,x ,d) (let ((v (logxor (aref ,x ,d) (aref ,x ,a))))
                          (declare (type u32 v)) (rotl32 v 8)))
     (setf (aref ,x ,c) (u32+ (aref ,x ,c) (aref ,x ,d))
           (aref ,x ,b) (let ((v (logxor (aref ,x ,b) (aref ,x ,c))))
                          (declare (type u32 v)) (rotl32 v 7)))))

(defun chacha20-block (state working out)
  "One ChaCha20 block: the 64-octet keystream for STATE into OUT."
  (declare (type (simple-array (unsigned-byte 32) (16)) state working)
           (type octets out)
           (optimize speed (safety 0)))
  (replace working state)
  (dotimes (i 10)
    (chacha-quarter-round working 0 4 8 12)
    (chacha-quarter-round working 1 5 9 13)
    (chacha-quarter-round working 2 6 10 14)
    (chacha-quarter-round working 3 7 11 15)
    (chacha-quarter-round working 0 5 10 15)
    (chacha-quarter-round working 1 6 11 12)
    (chacha-quarter-round working 2 7 8 13)
    (chacha-quarter-round working 3 4 9 14))
  (dotimes (i 16)
    (let ((v (u32+ (aref working i) (aref state i)))
          (j (* 4 i)))
      (declare (type u32 v) (type fixnum j))
      (setf (aref out j) (ldb (byte 8 0) v)
            (aref out (+ j 1)) (ldb (byte 8 8) v)
            (aref out (+ j 2)) (ldb (byte 8 16) v)
            (aref out (+ j 3)) (ldb (byte 8 24) v))))
  out)

(defun chacha20-state (key nonce counter)
  (check-octets key 32 "chacha20 key")
  (check-octets nonce 12 "chacha20 nonce")
  (let ((s (make-array 16 :element-type '(unsigned-byte 32))))
    (setf (aref s 0) #x61707865 (aref s 1) #x3320646e
          (aref s 2) #x79622d32 (aref s 3) #x6b206574)
    (dotimes (i 8)
      (setf (aref s (+ 4 i)) (octets->int-le key :start (* 4 i) :end (+ 4 (* 4 i)))))
    (setf (aref s 12) (ldb (byte 32 0) counter))
    (dotimes (i 3)
      (setf (aref s (+ 13 i)) (octets->int-le nonce :start (* 4 i) :end (+ 4 (* 4 i)))))
    s))

(defun chacha20-xor (key nonce data &key (counter 0))
  "XOR DATA with the ChaCha20 keystream for KEY (32), NONCE (12) starting at
block COUNTER.  Encryption and decryption are the same operation."
  (let* ((data (ensure-octets data))
         (state (chacha20-state key nonce counter))
         (working (make-array 16 :element-type '(unsigned-byte 32)))
         (ks (make-octets 64))
         (n (length data))
         (out (make-octets n)))
    (declare (type octets data ks out)
             (type (simple-array (unsigned-byte 32) (16)) state))
    (loop for off of-type fixnum from 0 below n by 64
          do (chacha20-block state working ks)
             (loop for i of-type fixnum from 0 below (min 64 (- n off))
                   do (setf (aref out (+ off i))
                            (logxor (aref data (+ off i)) (aref ks i))))
             (setf (aref state 12) (ldb (byte 32 0) (1+ (aref state 12)))))
    out))

;;; Poly1305.  The accumulator is an integer below 2^131; bignum arithmetic,
;;; not constant time.

(defconstant +poly1305-p+ (- (expt 2 130) 5))

(defun poly1305 (key message)
  "Poly1305 one-time authenticator: 16-octet tag of MESSAGE under the 32-octet KEY."
  (check-octets key 32 "poly1305 key")
  (let* ((message (ensure-octets message))
         (r (logand (octets->int-le key :start 0 :end 16)
                    #x0ffffffc0ffffffc0ffffffc0fffffff))
         (s (octets->int-le key :start 16 :end 32))
         (mask130 (1- (ash 1 130)))
         (acc 0)
         (n (length message)))
    (loop for off from 0 below n by 16
          do (let* ((end (min n (+ off 16)))
                    (block (+ (octets->int-le message :start off :end end)
                              (ash 1 (* 8 (- end off))))))
               (setf acc (* (+ acc block) r))
               ;; 2^130 = 5 (mod p): fold the high part down twice.
               (setf acc (+ (logand acc mask130) (* 5 (ash acc -130))))
               (setf acc (+ (logand acc mask130) (* 5 (ash acc -130))))))
    (when (>= acc +poly1305-p+) (decf acc +poly1305-p+))
    (int->octets-le (ldb (byte 128 0) (+ acc s)) 16)))

;;; AEAD (RFC 8439 section 2.8)

(defun pad16-length (n) (mod (- 16 (mod n 16)) 16))

(defun chacha20-poly1305-tag (key nonce ciphertext aad)
  (let* ((otk (subseq (chacha20-xor key nonce (make-octets 32)) 0 32))
         (la (length aad))
         (lc (length ciphertext))
         (mac-data (concat-octets aad (make-octets (pad16-length la))
                                  ciphertext (make-octets (pad16-length lc))
                                  (int->octets-le la 8) (int->octets-le lc 8))))
    (poly1305 (coerce-octets otk) mac-data)))

(defun chacha20-poly1305-encrypt (key nonce plaintext aad)
  "ChaCha20-Poly1305 seal: returns ciphertext || 16-octet tag."
  (let* ((aad (if aad (ensure-octets aad) (make-octets 0)))
         (ct (chacha20-xor key nonce plaintext :counter 1)))
    (concat-octets ct (chacha20-poly1305-tag key nonce ct aad))))

(defun chacha20-poly1305-decrypt (key nonce ciphertext aad)
  "ChaCha20-Poly1305 open of ciphertext || tag.  Signals AEAD-ERROR on a bad
tag or an input shorter than the tag."
  (let* ((aad (if aad (ensure-octets aad) (make-octets 0)))
         (data (ensure-octets ciphertext))
         (n (length data)))
    (when (< n 16) (error 'aead-error :message "ChaCha20-Poly1305: input shorter than tag"))
    (let ((ct (subseq-octets data 0 (- n 16)))
          (tag (subseq-octets data (- n 16))))
      (unless (ct-octets= tag (chacha20-poly1305-tag key nonce ct aad))
        (error 'aead-error))
      (chacha20-xor key nonce ct :counter 1))))
