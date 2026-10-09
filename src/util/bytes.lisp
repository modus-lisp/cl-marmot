;;;; bytes.lisp — octet vectors and the conversions every layer needs

(in-package #:cl-marmot)

(deftype octet () '(unsigned-byte 8))
(deftype octets () '(simple-array (unsigned-byte 8) (*)))

(defun make-octets (n &key (initial-element 0))
  (make-array n :element-type '(unsigned-byte 8) :initial-element initial-element))

(defun octets (&rest bytes)
  "Literal octet vector: (octets 1 2 3)."
  (coerce-octets bytes))

(defun coerce-octets (seq)
  "Copy SEQ (any sequence of integers 0..255) into a fresh simple octet vector."
  (let* ((n (length seq))
         (out (make-octets n)))
    (if (listp seq)
        (loop for b in seq for i from 0 do (setf (aref out i) b))
        (dotimes (i n) (setf (aref out i) (elt seq i))))
    out))

(defun concat-octets (&rest parts)
  "Concatenate octet vectors (NIL parts are skipped)."
  (let* ((parts (remove nil parts))
         (n (reduce #'+ parts :key #'length))
         (out (make-octets n))
         (pos 0))
    (dolist (p parts out)
      (replace out p :start1 pos)
      (incf pos (length p)))))

(defun subseq-octets (v start &optional end)
  (coerce-octets (subseq v start end)))

(defun octets= (a b)
  (and (= (length a) (length b))
       (every #'= a b)))

(defun ct-octets= (a b)
  "Constant-time equality for equal-length secrets (MAC tags)."
  (and (= (length a) (length b))
       (zerop (let ((acc 0))
                (dotimes (i (length a) acc)
                  (setf acc (logior acc (logxor (aref a i) (aref b i)))))))))

(defun octets< (a b)
  "Lexicographic order over octet vectors."
  (let ((n (min (length a) (length b))))
    (dotimes (i n (< (length a) (length b)))
      (cond ((< (aref a i) (aref b i)) (return t))
            ((> (aref a i) (aref b i)) (return nil))))))

;;; Integers <-> octets

(defun int->octets-be (n len)
  "Big-endian, exactly LEN bytes."
  (let ((out (make-octets len)))
    (loop for i from (1- len) downto 0
          do (setf (aref out i) (ldb (byte 8 0) n)
                   n (ash n -8)))
    out))

(defun octets->int-be (v &key (start 0) (end (length v)))
  (let ((n 0))
    (loop for i from start below end
          do (setf n (logior (ash n 8) (aref v i))))
    n))

(defun int->octets-le (n len)
  (let ((out (make-octets len)))
    (dotimes (i len out)
      (setf (aref out i) (ldb (byte 8 (* 8 i)) n)))))

(defun octets->int-le (v &key (start 0) (end (length v)))
  (let ((n 0))
    (loop for i from (1- end) downto start
          do (setf n (logior (ash n 8) (aref v i))))
    n))

;;; Strings <-> UTF-8

(defun string->utf8 (string)
  "Encode STRING as UTF-8 octets (no BOM, no normalization)."
  (let ((out (make-array (length string) :element-type '(unsigned-byte 8)
                                         :adjustable t :fill-pointer 0)))
    (loop for ch across string
          for c = (char-code ch)
          do (cond ((< c #x80) (vector-push-extend c out))
                   ((< c #x800)
                    (vector-push-extend (logior #xC0 (ash c -6)) out)
                    (vector-push-extend (logior #x80 (logand c #x3F)) out))
                   ((< c #x10000)
                    (vector-push-extend (logior #xE0 (ash c -12)) out)
                    (vector-push-extend (logior #x80 (logand (ash c -6) #x3F)) out)
                    (vector-push-extend (logior #x80 (logand c #x3F)) out))
                   (t
                    (vector-push-extend (logior #xF0 (ash c -18)) out)
                    (vector-push-extend (logior #x80 (logand (ash c -12) #x3F)) out)
                    (vector-push-extend (logior #x80 (logand (ash c -6) #x3F)) out)
                    (vector-push-extend (logior #x80 (logand c #x3F)) out))))
    (coerce-octets out)))

(define-condition utf8-error (error)
  ((position :initarg :position :reader utf8-error-position))
  (:report (lambda (c s) (format s "Invalid UTF-8 at byte ~D" (utf8-error-position c)))))

(defun utf8->string (octets &key (start 0) (end (length octets)))
  "Strict UTF-8 decode: rejects overlongs, surrogates and truncation."
  (let ((out (make-string-output-stream))
        (i start))
    (flet ((cont (k)
             (unless (< k end) (error 'utf8-error :position k))
             (let ((b (aref octets k)))
               (unless (= (logand b #xC0) #x80) (error 'utf8-error :position k))
               (logand b #x3F))))
      (loop while (< i end)
            do (let ((b (aref octets i)))
                 (multiple-value-bind (code len)
                     (cond ((< b #x80) (values b 1))
                           ((= (logand b #xE0) #xC0)
                            (values (logior (ash (logand b #x1F) 6) (cont (+ i 1))) 2))
                           ((= (logand b #xF0) #xE0)
                            (values (logior (ash (logand b #x0F) 12)
                                            (ash (cont (+ i 1)) 6) (cont (+ i 2)))
                                    3))
                           ((= (logand b #xF8) #xF0)
                            (values (logior (ash (logand b #x07) 18) (ash (cont (+ i 1)) 12)
                                            (ash (cont (+ i 2)) 6) (cont (+ i 3)))
                                    4))
                           (t (error 'utf8-error :position i)))
                   (when (or (and (= len 2) (< code #x80))
                             (and (= len 3) (< code #x800))
                             (and (= len 4) (< code #x10000))
                             (> code #x10FFFF)
                             (<= #xD800 code #xDFFF))
                     (error 'utf8-error :position i))
                   (write-char (code-char code) out)
                   (incf i len)))))
    (get-output-stream-string out)))

;;; Hex

(defun octets->hex (v)
  "Lowercase hex, no prefix."
  (let ((digits "0123456789abcdef")
        (out (make-string (* 2 (length v)))))
    (dotimes (i (length v) out)
      (let ((b (aref v i)))
        (setf (char out (* 2 i)) (char digits (ash b -4))
              (char out (1+ (* 2 i))) (char digits (logand b 15)))))))

(define-condition hex-error (error)
  ((string :initarg :string :reader hex-error-string))
  (:report (lambda (c s) (format s "Invalid hex: ~S" (hex-error-string c)))))

(defun hex->octets (s &key (lowercase-only nil))
  "Decode hex.  With LOWERCASE-ONLY, reject A-F (the Nostr/Marmot wire rule)."
  (unless (evenp (length s)) (error 'hex-error :string s))
  (let ((out (make-octets (/ (length s) 2))))
    (flet ((nib (ch)
             (let ((c (char-code ch)))
               (cond ((<= 48 c 57) (- c 48))
                     ((<= 97 c 102) (- c 87))
                     ((and (not lowercase-only) (<= 65 c 70)) (- c 55))
                     (t (error 'hex-error :string s))))))
      (dotimes (i (length out) out)
        (setf (aref out i) (logior (ash (nib (char s (* 2 i))) 4)
                                   (nib (char s (1+ (* 2 i))))))))))

(defun hex (s)
  "Shorthand for test vectors: hex string -> octets."
  (hex->octets s))
