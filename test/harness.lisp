;;;; harness.lisp — a dependency-free test harness
;;;;
;;;; (deftest name () body...)  registers a test; (is form) / (is-equal a b)
;;;; record checks; (run-tests) runs everything and returns T iff all passed.
;;;; Kept deliberately small so it runs unchanged on SBCL and on Modus.

(defpackage #:cl-marmot/test
  (:use #:common-lisp #:cl-marmot)
  (:local-nicknames (#:ev #:cl-nostr.event) (#:nip44 #:cl-nostr.nip44))
  (:export #:run-tests #:deftest))

(in-package #:cl-marmot/test)

;;; The library exports nothing yet, so tests see its internals: import every
;;; symbol whose home is CL-MARMOT (the whole library is loaded before this
;;; system, so they all exist now).
(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((lib (find-package '#:cl-marmot)))
    (do-symbols (s lib)
      (when (and (eq (symbol-package s) lib)
                 (not (find-symbol (symbol-name s) *package*)))
        (import s)))))

(defvar *tests* '())               ; list of (name . fn), newest first
(defvar *checks* 0)
(defvar *failures* '())
(defvar *current-test* nil)

(defmacro deftest (name () &body body)
  `(progn
     (setf *tests* (cons (cons ',name (lambda () ,@body))
                         (remove ',name *tests* :key #'car)))
     ',name))

(defun note-failure (fmt &rest args)
  (push (format nil "~A: ~?" *current-test* fmt args) *failures*))

(defmacro is (form &optional description)
  `(progn
     (incf *checks*)
     (unless ,form
       (note-failure "~A" (or ,description ',form)))))

(defmacro is-equal (expected actual &optional description)
  (let ((e (gensym)) (a (gensym)))
    `(let ((,e ,expected) (,a ,actual))
       (incf *checks*)
       (unless (equalp ,e ,a)
         (note-failure "~A~%    expected ~S~%    got      ~S"
                       (or ,description ',actual) ,e ,a)))))

(defmacro is-hex (expected-hex actual &optional description)
  "Compare octets against a hex string, reporting both in hex."
  (let ((e (gensym)) (a (gensym)))
    `(let ((,e ,expected-hex) (,a ,actual))
       (incf *checks*)
       (unless (and (typep ,a '(vector (unsigned-byte 8)))
                    (string= (string-downcase ,e) (octets->hex ,a)))
         (note-failure "~A~%    expected ~A~%    got      ~A"
                       (or ,description ',actual) ,e
                       (if (typep ,a '(vector (unsigned-byte 8))) (octets->hex ,a) ,a))))))

(defmacro signals (condition-type form &optional description)
  `(progn
     (incf *checks*)
     (unless (handler-case (progn ,form nil)
               (,condition-type () t)
               (error () nil))
       (note-failure "expected ~A from ~A" ',condition-type (or ,description ',form)))))

(defun run-tests (&key (only nil) (verbose nil))
  "Run registered tests (those whose name contains ONLY, if given)."
  (setf *checks* 0 *failures* '())
  (let ((ran 0))
    (dolist (entry (reverse *tests*))
      (when (or (null only) (search (string-upcase only) (symbol-name (car entry))))
        (let ((*current-test* (car entry))
              (before (length *failures*))
              (t0 (get-internal-real-time)))
          (incf ran)
          (handler-case (funcall (cdr entry))
            (error (c)
              (note-failure "unhandled ~A: ~A" (type-of c) c)))
          (when verbose
            (format t "~&~:[ok  ~;FAIL~] ~A~40T~,2Fs~%" (> (length *failures*) before) (car entry)
                    (/ (- (get-internal-real-time) t0) internal-time-units-per-second))
            (finish-output)))))
    (dolist (f (reverse *failures*))
      (format t "~&FAIL ~A~%" f))
    (format t "~&~D tests, ~D checks, ~D failures~%" ran *checks* (length *failures*))
    (null *failures*)))

(defun vector-path (name)
  "Path to an external test-vector file.  CL_MARMOT_VECTORS overrides the default."
  (let ((dir (or (cl-marmot::getenv "CL_MARMOT_VECTORS")
                 "/home/claude/marmot-ref/mls-implementations/test-vectors/")))
    (concatenate 'string dir name)))

(defun fixture-dir ()
  "test/fixtures/ of this checkout: CL_MARMOT_ROOT, else ASDF's idea of the
system's source directory."
  (let ((root (cl-marmot::getenv "CL_MARMOT_ROOT"))
        (asdf-dir (and (find-package "ASDF") (find-symbol "SYSTEM-SOURCE-DIRECTORY" "ASDF"))))
    (cond (root (concatenate 'string (string-right-trim "/" root) "/test/fixtures/"))
          ((and asdf-dir (fboundp asdf-dir))
           (namestring (merge-pathnames "test/fixtures/" (funcall asdf-dir "cl-marmot"))))
          (t (error "set CL_MARMOT_ROOT to the cl-marmot checkout")))))
