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

;;; Entropy: natrium's CSPRNG (OS entropy; no userspace fallback that could
;;; invent keys).

(defun random-octets (n) (coerce-octets (natrium:random-bytes n)))

(defun sleep-ms (ms) (sleep (/ ms 1000)))

(defun monotonic-ms ()
  (floor (* 1000 (get-internal-real-time)) internal-time-units-per-second))
