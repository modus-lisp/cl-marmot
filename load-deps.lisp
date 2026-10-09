;;;; load-deps.lisp — make cl-marmot's dependencies loadable
;;;;
;;;; cl-marmot needs the modus-lisp libraries natrium, secp256k1-fast, seal,
;;;; cl-nostr and json-simple (looked for in $MODUS_LISP, beside this checkout,
;;;; in ../modus-lisp and in ~/modus-lisp), and Quicklisp for bordeaux-threads
;;;; and cl-base64.  Load this file, then (ql:quickload :cl-marmot).

(let ((setup (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (if (probe-file setup)
      (load setup)
      (error "Quicklisp is required (for cl-nostr's dependencies): ~A not found" setup)))

(let* ((here (make-pathname :name nil :type nil :defaults (or *load-truename* *default-pathname-defaults*)))
       (env (uiop:getenv "MODUS_LISP"))
       (candidates (remove nil (list (and env (plusp (length env)) (uiop:ensure-directory-pathname env))
                                     (merge-pathnames "../" here)              ; siblings beside this checkout
                                     (merge-pathnames "../modus-lisp/" here)
                                     (merge-pathnames "modus-lisp/" (user-homedir-pathname)))))
       (root (find-if (lambda (d) (probe-file (merge-pathnames "cl-nostr/cl-nostr.asd" d))) candidates)))
  (unless root (error "modus-lisp libraries not found; set MODUS_LISP (tried ~{~A~^, ~})" candidates))
  ;; json-simple: cl-nostr's JSON library after its move off jzon (optional here)
  (dolist (lib '("natrium" "secp256k1-fast" "seal" "cl-nostr" "json-simple"))
    (let ((dir (merge-pathnames (concatenate 'string lib "/") root)))
      (when (probe-file dir) (push dir asdf:*central-registry*))))
  (push here asdf:*central-registry*))
