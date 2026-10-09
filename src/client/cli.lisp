;;;; cli.lisp — the `marmot` command line client
;;;;
;;;;   marmot init [--relay URL]... [--name NAME] [--nsec NSEC]
;;;;   marmot whoami | sync | watch [SECONDS] | groups | keypackage
;;;;   marmot create NAME [NPUB...]       marmot invite GROUP NPUB...
;;;;   marmot send GROUP TEXT...          marmot messages GROUP [N]
;;;;   marmot members GROUP               marmot rename GROUP NAME
;;;;   marmot remove GROUP NPUB...        marmot self-update GROUP
;;;;
;;;; GROUP is an MLS group id (or a unique prefix of one) or a group name.
;;;; State lives in $MARMOT_HOME/account.sexp (default
;;;; ~/.local/share/cl-marmot/).  Every command that touches the network syncs
;;;; first and saves afterwards.

(in-package #:cl-marmot)

(defun marmot-home ()
  (let ((env (getenv "MARMOT_HOME")))
    (if (and env (plusp (length env)))
        (concatenate 'string (string-right-trim "/" env) "/")
        (concatenate 'string (or (getenv "HOME") ".") "/.local/share/cl-marmot/"))))

(defun account-path () (concatenate 'string (marmot-home) "account.sexp"))

(defun %out (fmt &rest args) (apply #'format t fmt args) (finish-output))

(defun %short (hex) (subseq hex 0 (min 12 (length hex))))

(defun %display-pubkey (hex) (npub-encode (hex->octets hex)))

(defun %print-result (mg r)
  (let ((g (format nil "[~A]" (if (plusp (length (mg-name mg))) (mg-name mg) (%short (mg-id-hex mg))))))
    (case (getf r :type)
      (:message
       (%out "~A ~A: ~A~%" g (%short (%display-pubkey (getf r :sender)))
             (if (= (getf r :kind) 9) (getf r :content)
                 (format nil "(kind ~D) ~A" (getf r :kind) (getf r :content)))))
      (:joined (%out "~A joined (epoch ~D)~%" g (mg-epoch mg)))
      (:epoch (%out "~A epoch ~D~%" g (getf r :epoch)))
      (:member-added (%out "~A + ~A~%" g (npub-encode (getf r :account))))
      (:member-removed (%out "~A - ~A~%" g (npub-encode (getf r :account))))
      (:renamed (%out "~A renamed to ~S~%" g (getf r :name)))
      (:removed (%out "~A you were removed~%" g))
      (:rejected (%out "~A rejected input: ~A~%" g (getf r :reason)))
      ((:duplicate :undecryptable :stale :own-commit-echo :proposal) nil)
      (t (%out "~A ~S~%" g r)))))

(defun %load-or-die ()
  (unless (probe-file (account-path))
    (error "no account at ~A — run `marmot init` first" (account-path)))
  (let ((acct (load-account (account-path))))
    (setf (account-on-event acct) (lambda (a mg r) (declare (ignore a)) (%print-result mg r)))
    acct))

(defun %save (acct) (save-account acct (account-path)))

(defun %need-group (acct designator)
  (or (account-group acct designator) (error "no group ~S" designator)))

(defun %parse-flags (args)
  "Split ARGS into (values flags-plist positional)."
  (let ((flags '()) (pos '()))
    (loop while args
          do (let ((a (pop args)))
               (if (and (> (length a) 2) (string= "--" a :end2 2))
                   (push (cons (subseq a 2) (pop args)) flags)
                   (push a pos))))
    (values (nreverse flags) (nreverse pos))))

(defparameter *usage* "usage:
  marmot init [--relay URL]... [--name NAME] [--nsec NSEC]
  marmot whoami | sync | watch [SECONDS] | groups | keypackage
  marmot create NAME [NPUB...]       marmot invite GROUP NPUB...
  marmot send GROUP TEXT...          marmot messages GROUP [N]
  marmot members GROUP               marmot rename GROUP NAME
  marmot remove GROUP NPUB...        marmot self-update GROUP
  marmot promote GROUP NPUB          marmot demote GROUP NPUB
  marmot leave GROUP
GROUP is a group id, a unique id prefix, or a group name.
State: $MARMOT_HOME/account.sexp (default ~/.local/share/cl-marmot/)
")

(defun cli-main (args)
  (handler-case (%cli-dispatch args)
    (error (c) (%out "error: ~A~%" c) 1)))

(defun %cli-dispatch (args)
  (let ((cmd (first args)) (rest (rest args)))
    (cond
      ((or (null cmd) (member cmd '("help" "-h" "--help") :test #'string=))
       (%out "~A" *usage*) 0)
      ((string= cmd "init")
       (multiple-value-bind (flags pos) (%parse-flags rest)
         (declare (ignore pos))
         (when (probe-file (account-path)) (error "account already exists at ~A" (account-path)))
         (let* ((relays (or (mapcar #'cdr (remove "relay" flags :key #'car :test-not #'string=))
                            (list "wss://relay.damus.io")))
                (nsec (cdr (assoc "nsec" flags :test #'string=)))
                (acct (if nsec (make-account-from-secret (nsec-decode nsec) :relays relays)
                          (new-account :relays relays))))
           (setup-account acct :name (cdr (assoc "name" flags :test #'string=)))
           (%save acct)
           (%out "~A~%" (account-npub acct))
           0)))
      (t
       (let ((acct (%load-or-die)))
         (unwind-protect
              (progn (%cli-account-command acct cmd rest) 0)
           (%save acct)
           (close-account-pools acct)))))))

(defun %cli-account-command (acct cmd args)
  ;; only `sync` and `watch` narrate incoming traffic; other commands sync quietly
  (unless (member cmd '("sync" "watch") :test #'string=)
    (setf (account-on-event acct) nil))
  (flet ((group () (%need-group acct (first args))))
    (cond
      ((string= cmd "whoami") (%out "~A~%~A~%relays: ~{~A~^ ~}~%" (account-npub acct) (account-pubkey-hex acct)
                                   (account-relays acct)))
      ((string= cmd "keypackage") (let ((e (publish-key-package acct))) (%out "published ~A~%" (getf e :event-id))))
      ((string= cmd "sync") (sync acct))
      ((string= cmd "watch")
       (let ((until (+ (unix-time) (if args (parse-integer (first args)) 3600))))
         (loop while (< (unix-time) until)
               do (sync acct) (%save acct) (sleep 2))))
      ((string= cmd "groups")
       (sync acct)
       (loop for mg being the hash-values of (account-groups acct)
             do (%out "~A  epoch ~3D  ~2D members  ~8A  ~A~%" (mg-id-hex mg) (mg-epoch mg)
                      (length (mls-group-members (marmot-group-mls mg)))
                      (cond ((not (mls-group-active (marmot-group-mls mg))) "removed")
                            ((marmot-group-leaving mg) "leaving")
                            (t "active"))
                      (mg-name mg))))
      ((string= cmd "create")
       (let ((mg (create-group-with acct (first args) (rest args))))
         (%out "created ~A~%" (mg-id-hex mg))))
      ((string= cmd "invite") (sync acct) (%out "~S~%" (invite acct (group) (rest args))))
      ((string= cmd "remove") (sync acct) (remove-members acct (group) (rest args)) (%out "removed~%"))
      ((string= cmd "rename") (sync acct) (rename-group acct (group) (format nil "~{~A~^ ~}" (rest args)))
       (%out "renamed~%"))
      ((string= cmd "promote") (sync acct) (promote acct (group) (second args)) (%out "promoted~%"))
      ((string= cmd "demote") (sync acct) (demote acct (group) (second args)) (%out "demoted~%"))
      ((string= cmd "leave") (sync acct) (leave-group acct (group)) (%out "leave requested~%"))
      ((string= cmd "self-update") (sync acct) (self-update acct (group)) (%out "epoch ~D~%" (mg-epoch (group))))
      ((string= cmd "send")
       (sync acct)
       (send-message acct (group) (format nil "~{~A~^ ~}" (rest args)))
       (%out "sent~%"))
      ((string= cmd "messages")
       (sync acct)
       (let* ((mg (group))
              (n (if (second args) (parse-integer (second args)) 20)))
         (dolist (m (reverse (subseq (marmot-group-messages mg) 0 (min n (length (marmot-group-messages mg))))))
           (%print-result mg m))))
      ((string= cmd "members")
       (sync acct)
       (let ((mls (marmot-group-mls (group))))
         (loop for (i . ln) in (mls-group-members mls)
               do (%out "~3D  ~A~:[~; (admin)~]~:[~; (you)~]~%" i (npub-encode (leaf-account ln))
                        (member (leaf-account ln) (group-admins mls) :test #'octets=)
                        (= i (mls-group-own-leaf mls))))))
      (t (error "unknown command ~S" cmd)))))
