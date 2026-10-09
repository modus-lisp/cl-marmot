;;;; load-deps.lisp — make cl-marmot's dependencies loadable
;;;;
;;;; cl-marmot needs the modus-lisp libraries natrium, secp256k1-fast, seal and
;;;; cl-nostr (looked for in $MODUS_LISP, ../modus-lisp, ~/modus-lisp), and
;;;; through cl-nostr a few Quicklisp systems (ironclad, cl-base64, jzon,
;;;; bordeaux-threads).  Load this file, then (ql:quickload :cl-marmot).

(let ((setup (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (if (probe-file setup)
      (load setup)
      (error "Quicklisp is required (for cl-nostr's dependencies): ~A not found" setup)))

(let* ((here (make-pathname :name nil :type nil :defaults (or *load-truename* *default-pathname-defaults*)))
       (env (uiop:getenv "MODUS_LISP"))
       (candidates (remove nil (list (and env (plusp (length env)) (uiop:ensure-directory-pathname env))
                                     (merge-pathnames "../modus-lisp/" here)
                                     (merge-pathnames "modus-lisp/" (user-homedir-pathname)))))
       (root (find-if (lambda (d) (probe-file (merge-pathnames "cl-nostr/cl-nostr.asd" d))) candidates)))
  (unless root (error "modus-lisp libraries not found; set MODUS_LISP (tried ~{~A~^, ~})" candidates))
  (dolist (lib '("natrium" "secp256k1-fast" "seal" "cl-nostr"))
    (push (merge-pathnames (concatenate 'string lib "/") root) asdf:*central-registry*))
  (push here asdf:*central-registry*))
