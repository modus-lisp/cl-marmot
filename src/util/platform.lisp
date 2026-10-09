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

;;; TCP
;;;
;;; Through the SB-BSD-SOCKETS surface, which SBCL provides natively and Modus
;;; provides as a compatibility shim.  Symbols are resolved at run time.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (unless (find-package "SB-BSD-SOCKETS")
    (ignore-errors (require "SB-BSD-SOCKETS"))))

(defun %sym (package name)
  (or (and (find-package package) (find-symbol name package))
      (error "~A::~A is not available in this Lisp" package name)))

(defun %call (package name &rest args)
  (apply (symbol-function (%sym package name)) args))

(defun tcp-connect (host port)
  "Open a TCP connection.  Returns (values binary-io-stream socket)."
  (let* ((address (%call "SB-BSD-SOCKETS" "HOST-ENT-ADDRESS"
                         (%call "SB-BSD-SOCKETS" "GET-HOST-BY-NAME" host)))
         (socket (make-instance (%sym "SB-BSD-SOCKETS" "INET-SOCKET")
                                :type :stream :protocol :tcp)))
    (handler-case (%call "SB-BSD-SOCKETS" "SOCKET-CONNECT" socket address port)
      (error (c)
        (ignore-errors (%call "SB-BSD-SOCKETS" "SOCKET-CLOSE" socket))
        (error c)))
    (values (%call "SB-BSD-SOCKETS" "SOCKET-MAKE-STREAM" socket
                   :input t :output t :element-type '(unsigned-byte 8) :buffering :full)
            socket)))

(defun tcp-close (socket)
  (ignore-errors (%call "SB-BSD-SOCKETS" "SOCKET-CLOSE" socket)))

(defun sleep-ms (ms) (sleep (/ ms 1000)))

(defun monotonic-ms ()
  (floor (* 1000 (get-internal-real-time)) internal-time-units-per-second))
