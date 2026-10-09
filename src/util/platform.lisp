;;;; platform.lisp — the only implementation-specific code in cl-marmot
;;;;
;;;; Symbols are looked up at RUN time with FIND-SYMBOL rather than written as
;;;; package-qualified names, so this file READS on every implementation even
;;;; when SB-EXT / SB-BSD-SOCKETS do not exist (Modus provides both packages as
;;;; a compatibility surface; other Lisps can add a branch here).

(in-package #:cl-marmot)

(defun %ext-fn (package name)
  (let* ((pkg (find-package package))
         (sym (and pkg (find-symbol name pkg))))
    (and sym (fboundp sym) (symbol-function sym))))

(defun getenv (name)
  (let ((fn (%ext-fn "SB-EXT" "POSIX-GETENV")))
    (and fn (funcall fn name))))

;;; Time

(defconstant +unix-epoch-universal+ 2208988800)

(defun unix-time ()
  "Current Unix time in whole seconds."
  (- (get-universal-time) +unix-epoch-universal+))

;;; Entropy
;;;
;;; /dev/urandom read as a binary stream: portable, and correct on Linux and
;;; every BSD.  There is no fallback to a userspace PRNG — a client that cannot
;;; get kernel entropy must not invent keys.

(defun random-octets (n)
  (let ((out (make-octets n)))
    (with-open-file (in "/dev/urandom" :element-type '(unsigned-byte 8))
      (let ((got (read-sequence out in)))
        (unless (= got n)
          (error "short read from /dev/urandom: ~D of ~D" got n))))
    out))
