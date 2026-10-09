;;;; sha1.lisp — SHA-1 (FIPS 180-4), for the RFC 6455 websocket handshake only
;;;;
;;;; Sec-WebSocket-Accept is base64(SHA-1(key || GUID)).  Nothing in Marmot,
;;;; MLS or Nostr uses SHA-1 for security.

(in-package #:cl-marmot)

(defun sha1 (data)
  (let* ((n (length data))
         (full (* 64 (floor n 64)))
         (tail (md-tail data 64 8))
         (h (list #x67452301 #xEFCDAB89 #x98BADCFE #x10325476 #xC3D2E1F0))
         (w (make-array 80 :element-type '(unsigned-byte 32))))
    (flet ((block! (buf off)
             (dotimes (i 16)
               (setf (aref w i) (octets->int-be buf :start (+ off (* 4 i)) :end (+ off (* 4 i) 4))))
             (loop for i from 16 below 80
                   do (let ((x (logxor (aref w (- i 3)) (aref w (- i 8)) (aref w (- i 14)) (aref w (- i 16)))))
                        (setf (aref w i) (ldb (byte 32 0) (logior (ash x 1) (ash x -31))))))
             (destructuring-bind (a b c d e) h
               (dotimes (i 80)
                 (multiple-value-bind (f k)
                     (cond ((< i 20) (values (logior (logand b c) (logand (logxor b #xFFFFFFFF) d)) #x5A827999))
                           ((< i 40) (values (logxor b c d) #x6ED9EBA1))
                           ((< i 60) (values (logior (logand b c) (logand b d) (logand c d)) #x8F1BBCDC))
                           (t (values (logxor b c d) #xCA62C1D6)))
                   (let ((tmp (ldb (byte 32 0) (+ (ldb (byte 32 0) (logior (ash a 5) (ash a -27))) f e k (aref w i)))))
                     (setf e d d c c (ldb (byte 32 0) (logior (ash b 30) (ash b -2))) b a a tmp))))
               (setf h (mapcar (lambda (x y) (ldb (byte 32 0) (+ x y))) h (list a b c d e))))))
      (loop for off from 0 below full by 64 do (block! data off))
      (loop for off from 0 below (length tail) by 64 do (block! tail off))
      (apply #'concat-octets (mapcar (lambda (x) (int->octets-be x 4)) h)))))
