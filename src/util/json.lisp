;;;; json.lisp — JSON reader/writer with NIP-01 string escaping
;;;;
;;;; Representation (chosen so every JSON value has exactly one Lisp shape):
;;;;   object  -> (:obj ("key" . value) ...)      keys in document order
;;;;   array   -> simple-vector
;;;;   string  -> string
;;;;   number  -> integer, or double-float when it has a fraction/exponent
;;;;   true / false / null -> :true / :false / :null
;;;;
;;;; The writer emits no insignificant whitespace and escapes strings exactly
;;;; as NIP-01 requires (only " \ \n \r \t \b \f; everything else verbatim),
;;;; which is what Nostr event ids hash.  The reader can reject duplicate
;;;; object keys, which the Marmot app-payload decoder requires.

(in-package #:cl-marmot)

(define-condition json-error (error)
  ((message :initarg :message :reader json-error-message)
   (position :initarg :position :initform nil :reader json-error-position))
  (:report (lambda (c s)
             (format s "JSON: ~A~@[ at ~D~]" (json-error-message c) (json-error-position c)))))

;;; Constructors / accessors

(defun jobj (&rest kvs)
  "(jobj \"a\" 1 \"b\" 2) => (:obj (\"a\" . 1) (\"b\" . 2))"
  (cons :obj (loop for (k v) on kvs by #'cddr collect (cons k v))))

(defun jobj-p (x) (and (consp x) (eq (car x) :obj)))

(defun jget (obj key &optional default)
  (let ((cell (and (jobj-p obj) (assoc key (cdr obj) :test #'string=))))
    (if cell (cdr cell) default)))

(defun jarr (&rest items) (coerce items 'simple-vector))

;;; Writer

(defun json-write-string (string stream)
  (write-char #\" stream)
  (loop for ch across string
        do (case ch
             (#\" (write-string "\\\"" stream))
             (#\\ (write-string "\\\\" stream))
             (#\Newline (write-string "\\n" stream))
             (#\Return (write-string "\\r" stream))
             (#\Tab (write-string "\\t" stream))
             (#\Backspace (write-string "\\b" stream))
             (#\Page (write-string "\\f" stream))
             (t (write-char ch stream))))
  (write-char #\" stream))

(defun json-write (value stream)
  (cond ((eq value :true) (write-string "true" stream))
        ((eq value :false) (write-string "false" stream))
        ((or (eq value :null) (null value)) (write-string "null" stream))
        ((eq value t) (write-string "true" stream))
        ((stringp value) (json-write-string value stream))
        ((integerp value) (format stream "~D" value))
        ((realp value)
         (let ((*read-default-float-format* 'double-float))
           (format stream "~F" (coerce value 'double-float))))
        ((jobj-p value)
         (write-char #\{ stream)
         (loop for (k . v) in (cdr value)
               for first = t then nil
               do (unless first (write-char #\, stream))
                  (json-write-string k stream)
                  (write-char #\: stream)
                  (json-write v stream))
         (write-char #\} stream))
        ((vectorp value)
         (write-char #\[ stream)
         (loop for item across value
               for first = t then nil
               do (unless first (write-char #\, stream))
                  (json-write item stream))
         (write-char #\] stream))
        ((listp value)                  ; a plain list writes as an array
         (json-write (coerce value 'simple-vector) stream))
        (t (error 'json-error :message (format nil "cannot encode ~S" value)))))

(defun to-json (value)
  (with-output-to-string (s) (json-write value s)))

;;; Reader

(defvar *json-reject-duplicate-keys* nil)

(defun parse-json (string &key (reject-duplicate-keys *json-reject-duplicate-keys*))
  "Parse exactly one JSON value from STRING (trailing whitespace allowed)."
  (let ((pos 0) (len (length string)))
    (labels ((fail (msg) (error 'json-error :message msg :position pos))
             (peek () (if (< pos len) (char string pos) (fail "unexpected end")))
             (skip-ws ()
               (loop while (and (< pos len)
                                (member (char string pos) '(#\Space #\Tab #\Newline #\Return)))
                     do (incf pos)))
             (expect (ch)
               (skip-ws)
               (unless (and (< pos len) (char= (char string pos) ch))
                 (fail (format nil "expected ~C" ch)))
               (incf pos))
             (literal (word value)
               (unless (and (<= (+ pos (length word)) len)
                            (string= word string :start2 pos :end2 (+ pos (length word))))
                 (fail "bad literal"))
               (incf pos (length word))
               value)
             (hex4 ()
               (when (> (+ pos 4) len) (fail "short \\u escape"))
               (prog1 (or (parse-integer string :start pos :end (+ pos 4) :radix 16
                                                :junk-allowed t)
                          (fail "bad \\u escape"))
                 (incf pos 4)))
             (read-string ()
               (incf pos)               ; opening quote
               (let ((out (make-string-output-stream)))
                 (loop
                   (let ((ch (peek)))
                     (incf pos)
                     (cond ((char= ch #\") (return (get-output-stream-string out)))
                           ((char= ch #\\)
                            (let ((e (peek)))
                              (incf pos)
                              (case e
                                (#\" (write-char #\" out))
                                (#\\ (write-char #\\ out))
                                (#\/ (write-char #\/ out))
                                (#\b (write-char #\Backspace out))
                                (#\f (write-char #\Page out))
                                (#\n (write-char #\Newline out))
                                (#\r (write-char #\Return out))
                                (#\t (write-char #\Tab out))
                                (#\u (let ((c (hex4)))
                                       (when (<= #xD800 c #xDBFF)
                                         (unless (and (< (+ pos 1) len)
                                                      (char= (char string pos) #\\)
                                                      (char= (char string (1+ pos)) #\u))
                                           (fail "lone surrogate"))
                                         (incf pos 2)
                                         (let ((lo (hex4)))
                                           (unless (<= #xDC00 lo #xDFFF) (fail "bad surrogate"))
                                           (setf c (+ #x10000 (ash (- c #xD800) 10) (- lo #xDC00)))))
                                       (when (<= #xDC00 c #xDFFF) (fail "lone surrogate"))
                                       (write-char (code-char c) out)))
                                (t (fail "bad escape")))))
                           (t (write-char ch out)))))))
             (read-number ()
               (let ((start pos))
                 (when (char= (peek) #\-) (incf pos))
                 (loop while (and (< pos len) (digit-char-p (char string pos))) do (incf pos))
                 (let ((int-end pos) (float nil))
                   (when (and (< pos len) (char= (char string pos) #\.))
                     (setf float t) (incf pos)
                     (loop while (and (< pos len) (digit-char-p (char string pos))) do (incf pos)))
                   (when (and (< pos len) (char-equal (char string pos) #\e))
                     (setf float t) (incf pos)
                     (when (and (< pos len) (member (char string pos) '(#\+ #\-))) (incf pos))
                     (loop while (and (< pos len) (digit-char-p (char string pos))) do (incf pos)))
                   (when (= int-end start) (fail "bad number"))
                   (if float
                       (let ((*read-default-float-format* 'double-float)
                             (*read-eval* nil))
                         (coerce (read-from-string (substitute #\d #\e (string-downcase
                                                                         (subseq string start pos))))
                                 'double-float))
                       (parse-integer string :start start :end pos)))))
             (read-value ()
               (skip-ws)
               (let ((ch (peek)))
                 (cond ((char= ch #\{) (read-object))
                       ((char= ch #\[) (read-array))
                       ((char= ch #\") (read-string))
                       ((char= ch #\t) (literal "true" :true))
                       ((char= ch #\f) (literal "false" :false))
                       ((char= ch #\n) (literal "null" :null))
                       ((or (char= ch #\-) (digit-char-p ch)) (read-number))
                       (t (fail "unexpected character")))))
             (read-array ()
               (incf pos)
               (skip-ws)
               (if (char= (peek) #\])
                   (progn (incf pos) (vector))
                   (let ((items '()))
                     (loop
                       (push (read-value) items)
                       (skip-ws)
                       (let ((ch (peek)))
                         (incf pos)
                         (cond ((char= ch #\,))
                               ((char= ch #\]) (return (coerce (nreverse items) 'simple-vector)))
                               (t (fail "expected , or ]"))))))))
             (read-object ()
               (incf pos)
               (skip-ws)
               (if (char= (peek) #\})
                   (progn (incf pos) (list :obj))
                   (let ((pairs '()))
                     (loop
                       (skip-ws)
                       (unless (char= (peek) #\") (fail "expected key"))
                       (let ((k (read-string)))
                         (when (and reject-duplicate-keys
                                    (assoc k pairs :test #'string=))
                           (fail (format nil "duplicate key ~S" k)))
                         (expect #\:)
                         (push (cons k (read-value)) pairs))
                       (skip-ws)
                       (let ((ch (peek)))
                         (incf pos)
                         (cond ((char= ch #\,))
                               ((char= ch #\}) (return (cons :obj (nreverse pairs))))
                               (t (fail "expected , or }")))))))))
      (let ((v (read-value)))
        (skip-ws)
        (unless (= pos len) (fail "trailing data"))
        v))))
