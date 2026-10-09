;;;; tls-codec.lisp — TLS presentation language with MLS / QUIC vector prefixes
;;;;
;;;; MLS (RFC 9420 §2.1.2) prefixes variable-length vectors with a QUIC-style
;;;; varint limited to 30 bits (1, 2 or 4 bytes; the 8-byte form is invalid)
;;;; and requires the shortest encoding.  The Marmot binary profile
;;;; (foundation/canonical-encoding.md) uses the same prefix with the 8-byte
;;;; form allowed.  Both decoders reject non-minimal prefixes, which is what
;;;; makes decode -> re-encode the identity and lets us hash re-encoded bytes.

(in-package #:cl-marmot)

(define-condition decode-error (error)
  ((message :initarg :message :reader decode-error-message))
  (:report (lambda (c s) (format s "decode: ~A" (decode-error-message c)))))

(defun decode-fail (fmt &rest args)
  (error 'decode-error :message (apply #'format nil fmt args)))

;;; ---------------------------------------------------------------------------
;;; Writer

(defun make-writer ()
  (make-array 64 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))

(defun writer-octets (w) (coerce-octets w))

(defmacro with-writer ((w) &body body)
  "Evaluate BODY with W bound to a fresh writer; return the octets written."
  `(let ((,w (make-writer)))
     ,@body
     (writer-octets ,w)))

(defun w-u8 (w n) (vector-push-extend (ldb (byte 8 0) n) w))
(defun w-u16 (w n) (w-u8 w (ash n -8)) (w-u8 w n))
(defun w-u32 (w n) (loop for s from 24 downto 0 by 8 do (w-u8 w (ash n (- s)))))
(defun w-u64 (w n) (loop for s from 56 downto 0 by 8 do (w-u8 w (ash n (- s)))))

(defun w-bytes (w octets)
  "Raw bytes, no prefix (opaque name[N])."
  (loop for b across octets do (vector-push-extend b w)))

(defun w-varint (w n &key (quic nil))
  (cond ((< n 64) (w-u8 w n))
        ((< n 16384) (w-u16 w (logior #x4000 n)))
        ((< n 1073741824) (w-u32 w (logior #x80000000 n)))
        ((and quic (< n 4611686018427387904))
         (w-u64 w (logior #xC000000000000000 n)))
        (t (error "varint too large: ~D" n))))

(defun w-opaque (w octets &key quic)
  "opaque name<V>: varint length then bytes."
  (w-varint w (length octets) :quic quic)
  (w-bytes w octets))

(defun w-vector (w items fn &key quic)
  "Type items<V>: encode each item with (FN writer item) into a sub-buffer,
then write varint byte-length + body."
  (let ((body (with-writer (sub) (dolist (it (coerce items 'list)) (funcall fn sub it)))))
    (w-opaque w body :quic quic)))

(defun w-optional (w value fn)
  "optional<T>: 0 or (1 followed by T)."
  (if value
      (progn (w-u8 w 1) (funcall fn w value))
      (w-u8 w 0)))

;;; ---------------------------------------------------------------------------
;;; Reader

(defstruct (reader (:constructor %make-reader (data pos end)))
  (data (make-octets 0) :type (simple-array (unsigned-byte 8) (*)))
  (pos 0 :type fixnum)
  (end 0 :type fixnum))

(defun make-reader (octets &key (start 0) (end (length octets)))
  (%make-reader (if (typep octets '(simple-array (unsigned-byte 8) (*)))
                    octets
                    (coerce-octets octets))
                start end))

(defun reader-remaining (r) (- (reader-end r) (reader-pos r)))
(defun reader-done-p (r) (= (reader-pos r) (reader-end r)))

(defun reader-expect-done (r what)
  (unless (reader-done-p r)
    (decode-fail "~D trailing bytes after ~A" (reader-remaining r) what)))

(defun %need (r n)
  (when (> n (reader-remaining r))
    (decode-fail "truncated: need ~D bytes, have ~D" n (reader-remaining r))))

(defun r-u8 (r)
  (%need r 1)
  (prog1 (aref (reader-data r) (reader-pos r)) (incf (reader-pos r))))

(defun r-uint (r nbytes)
  (%need r nbytes)
  (let ((n 0) (d (reader-data r)) (p (reader-pos r)))
    (dotimes (i nbytes) (setf n (logior (ash n 8) (aref d (+ p i)))))
    (incf (reader-pos r) nbytes)
    n))

(defun r-u16 (r) (r-uint r 2))
(defun r-u32 (r) (r-uint r 4))
(defun r-u64 (r) (r-uint r 8))

(defun r-bytes (r n)
  (%need r n)
  (let ((out (make-octets n)))
    (replace out (reader-data r) :start2 (reader-pos r) :end2 (+ (reader-pos r) n))
    (incf (reader-pos r) n)
    out))

(defun r-varint (r &key quic)
  (let* ((b0 (r-u8 r))
         (prefix (ash b0 -6))
         (len (ash 1 prefix))
         (n (logand b0 #x3F)))
    (when (and (= prefix 3) (not quic))
      (decode-fail "8-byte varint not allowed in MLS"))
    (loop repeat (1- len) do (setf n (logior (ash n 8) (r-u8 r))))
    ;; minimal encoding
    (when (or (and (= len 2) (< n 64))
              (and (= len 4) (< n 16384))
              (and (= len 8) (< n 1073741824)))
      (decode-fail "non-minimal varint"))
    n))

(defun r-opaque (r &key quic max)
  (let ((n (r-varint r :quic quic)))
    (when (and max (> n max)) (decode-fail "opaque length ~D exceeds ~D" n max))
    (r-bytes r n)))

(defun r-sub-reader (r &key quic)
  "Read a varint length and return a reader over exactly that span."
  (let ((n (r-varint r :quic quic)))
    (%need r n)
    (prog1 (%make-reader (reader-data r) (reader-pos r) (+ (reader-pos r) n))
      (incf (reader-pos r) n))))

(defun r-vector (r fn &key quic)
  "Read Type items<V>: FN is called with a sub-reader until it is exhausted.
Returns a list."
  (let ((sub (r-sub-reader r :quic quic))
        (items '()))
    (loop until (reader-done-p sub)
          do (push (funcall fn sub) items))
    (nreverse items)))

(defun r-optional (r fn)
  (case (r-u8 r)
    (0 nil)
    (1 (funcall fn r))
    (t (decode-fail "bad optional presence byte"))))

(defun decode-exactly (octets fn what)
  "Decode OCTETS with FN, requiring every byte to be consumed."
  (let* ((r (make-reader octets))
         (v (funcall fn r)))
    (reader-expect-done r what)
    v))
