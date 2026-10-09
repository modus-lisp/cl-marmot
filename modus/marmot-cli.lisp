;;;; modus/marmot-cli.lisp -- one `marmot` command under Modus, in this process.
;;;;
;;;; bin/marmot-modus runs this with the arguments as a JSON array in MARMOT_ARGV
;;;; (Modus has no *POSIX-ARGV*).  No daemon and no threads: on Modus a native
;;;; thread may not store its objects into another thread's data, so cl-marmot
;;;; talks to relays with the :DIRECT transport (src/client/account.lisp).

(let ((*standard-output* (make-broadcast-stream)))
  (load (merge-pathnames "../load-deps.lisp" *load-truename*))
  (funcall (find-symbol "QUICKLOAD" "QL") "cl-marmot" :silent t))
(defvar *argv* (coerce (cl-marmot::parse-json (cl-marmot::getenv "MARMOT_ARGV")) 'list))
(defvar *code* (marmot:cli-main *argv*))
(finish-output)
(sys-exit *code*)
