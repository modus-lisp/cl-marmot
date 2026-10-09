;;;; store.lisp — saving and restoring an account (identity, KeyPackages, groups)
;;;;
;;;; The file is one READable s-expression made only of lists, strings,
;;;; integers and keywords; octets are lowercase hex strings.  It is read with
;;;; *READ-EVAL* NIL in the CL-MARMOT package.  It contains every secret the
;;;; account has (Nostr key, MLS private keys, epoch secrets): protect it.
;;;; State is written to a temporary file and renamed into place, so a crash
;;;; mid-write leaves the previous state intact.

(in-package #:cl-marmot)

(defun %h (x) (and x (octets->hex x)))
(defun %o (x) (and x (hex->octets x)))

;;; MLS group

(defun %secret-tree->sexp (st)
  (list :n-leaves (secret-tree-n-leaves st)
        :nodes (loop for k being the hash-keys of (secret-tree-nodes st) using (hash-value v)
                     collect (list k (%h v)))
        :ratchets (loop for k being the hash-keys of (secret-tree-ratchets st) using (hash-value r)
                        collect (list (car k) (cdr k) (%h (ratchet-secret r)) (ratchet-generation r)
                                      (loop for g being the hash-keys of (ratchet-skipped r) using (hash-value kn)
                                            collect (list g (%h (car kn)) (%h (cdr kn))))))))

(defun %sexp->secret-tree (s)
  (let ((st (%make-secret-tree :n-leaves (getf s :n-leaves))))
    (loop for (k v) in (getf s :nodes) do (setf (gethash k (secret-tree-nodes st)) (%o v)))
    (loop for (leaf type secret gen skipped) in (getf s :ratchets)
          do (let ((r (make-ratchet (%o secret))))
               (setf (ratchet-generation r) gen)
               (loop for (g k n) in skipped do (setf (gethash g (ratchet-skipped r)) (cons (%o k) (%o n))))
               (setf (gethash (cons leaf type) (secret-tree-ratchets st)) r)))
    st))

(defparameter +epoch-secret-slots+
  '(joiner-secret welcome-secret epoch-secret sender-data-secret encryption-secret exporter-secret
    external-secret confirmation-key membership-key resumption-psk epoch-authenticator init-secret))

(defun %epoch-secrets->sexp (es)
  (loop for slot in +epoch-secret-slots+
        append (list (intern (symbol-name slot) :keyword)
                     (%h (funcall (intern (format nil "EPOCH-SECRETS-~A" slot) '#:cl-marmot) es)))))

(defun %sexp->epoch-secrets (s)
  (apply #'make-epoch-secrets (loop for (k v) on s by #'cddr append (list k (%o v)))))

(defun mls-group->sexp (g)
  (list :context (%h (tls-serialize 'group-context (mls-group-context g)))
        :tree (%h (with-writer (w) (encode-ratchet-tree w (rt-export-nodes (mls-group-tree g)))))
        :own-leaf (mls-group-own-leaf g)
        :sig-sk (%h (mls-group-sig-sk g))
        :node-sks (loop for k being the hash-keys of (mls-group-node-sks g) using (hash-value v)
                        collect (list k (%h v)))
        :secrets (%epoch-secrets->sexp (mls-group-secrets g))
        :secret-tree (%secret-tree->sexp (mls-group-secret-tree g))
        :interim-hash (%h (mls-group-interim-hash g))
        :confirmation-tag (%h (mls-group-confirmation-tag g))
        :proposals (mapcar (lambda (p) (list (%h (getf p :ref))
                                             (%h (tls-serialize 'proposal (getf p :proposal)))
                                             (getf p :sender) (%h (getf p :digest))))
                           (mls-group-proposals g))
        :external-psks (mapcar (lambda (c) (list (%h (car c)) (%h (cdr c)))) (mls-group-external-psks g))
        :resumption-psks (mapcar (lambda (c) (list (car c) (%h (cdr c)))) (mls-group-resumption-psks g))
        :active (mls-group-active g)))

(defun sexp->mls-group (s)
  (let ((sks (make-hash-table)))
    (loop for (k v) in (getf s :node-sks) do (setf (gethash k sks) (%o v)))
    (make-mls-group
     :context (tls-deserialize 'group-context (%o (getf s :context)))
     :tree (make-ratchet-tree-from-nodes (decode-exactly (%o (getf s :tree)) #'decode-ratchet-tree "tree"))
     :own-leaf (getf s :own-leaf)
     :sig-sk (%o (getf s :sig-sk))
     :node-sks sks
     :secrets (%sexp->epoch-secrets (getf s :secrets))
     :secret-tree (%sexp->secret-tree (getf s :secret-tree))
     :interim-hash (%o (getf s :interim-hash))
     :confirmation-tag (%o (getf s :confirmation-tag))
     :proposals (loop for (ref p sender digest) in (getf s :proposals)
                      collect (list :ref (%o ref) :proposal (tls-deserialize 'proposal (%o p)) :sender sender
                                    :digest (%o digest)))
     :external-psks (loop for (k v) in (getf s :external-psks) collect (cons (%o k) (%o v)))
     :resumption-psks (loop for (e v) in (getf s :resumption-psks) collect (cons e (%o v)))
     :active (getf s :active))))

;;; Marmot group

(defun %message->sexp (m)
  ;; plists of strings/integers/keywords already; tags are lists of strings
  m)

(defun marmot-group->sexp (mg)
  (list :mls (mls-group->sexp (marmot-group-mls mg))
        :retained (mapcar #'mls-group->sexp (marmot-group-retained mg))
        :seen (loop for k being the hash-keys of (marmot-group-seen mg) collect k)
        :messages (mapcar #'%message->sexp (marmot-group-messages mg))
        :leaving (marmot-group-leaving mg)
        :log (mapcar (lambda (n) (loop for (k v) on n by #'cddr
                                       append (list k (if (typep v '(vector (unsigned-byte 8))) (%h v) v))))
                     (marmot-group-log mg))))

(defun sexp->marmot-group (s)
  (let ((mg (make-marmot-group :mls (sexp->mls-group (getf s :mls))
                               :retained (mapcar #'sexp->mls-group (getf s :retained))
                               :messages (getf s :messages)
                               :log (getf s :log)
                               :leaving (getf s :leaving))))
    (dolist (k (getf s :seen)) (setf (gethash k (marmot-group-seen mg)) t))
    mg))

;;; Account

(defun account->sexp (acct)
  (list :version 1
        :sk (%h (account-sk acct))
        :relays (account-relays acct)
        :key-packages (mapcar (lambda (e)
                                (let ((b (getf e :bundle)))
                                  (list :kp (%h (tls-serialize 'key-package (key-package-bundle-key-package b)))
                                        :init-sk (%h (key-package-bundle-init-sk b))
                                        :leaf-sk (%h (key-package-bundle-leaf-sk b))
                                        :sig-sk (%h (key-package-bundle-sig-sk b))
                                        :event-id (getf e :event-id) :ref (getf e :ref) :d (%h (getf e :d)))))
                              (account-key-packages acct))
        :groups (loop for mg being the hash-values of (account-groups acct) collect (marmot-group->sexp mg))
        :seen-wraps (loop for k being the hash-keys of (account-seen-wraps acct) collect k)
        :seen-group-events (loop for k being the hash-keys of (account-seen-group-events acct) collect k)
        :last-sync (account-last-sync acct)))

(defun sexp->account (s)
  (unless (eql (getf s :version) 1) (error "unknown account file version ~S" (getf s :version)))
  (let ((acct (make-account-from-secret (%o (getf s :sk)) :relays (getf s :relays))))
    (setf (account-key-packages acct)
          (mapcar (lambda (e)
                    (list :bundle (make-key-package-bundle
                                   :key-package (tls-deserialize 'key-package (%o (getf e :kp)))
                                   :init-sk (%o (getf e :init-sk)) :leaf-sk (%o (getf e :leaf-sk))
                                   :sig-sk (%o (getf e :sig-sk)))
                          :event-id (getf e :event-id) :ref (getf e :ref) :d (%o (getf e :d))))
                  (getf s :key-packages)))
    (dolist (gs (getf s :groups))
      (let ((mg (sexp->marmot-group gs)))
        (setf (gethash (mg-id-hex mg) (account-groups acct)) mg)))
    (dolist (k (getf s :seen-wraps)) (setf (gethash k (account-seen-wraps acct)) t))
    (dolist (k (getf s :seen-group-events)) (setf (gethash k (account-seen-group-events acct)) t))
    (setf (account-last-sync acct) (or (getf s :last-sync) 0))
    acct))

(defun chmod-private (path)
  "Make PATH readable and writable by its owner only (where the Lisp exposes
chmod: SB-POSIX on SBCL and in Modus's compatibility surface)."
  (let ((chmod (%ext-fn "SB-POSIX" "CHMOD")))
    (when chmod (ignore-errors (funcall chmod (namestring path) #o600)))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (unless (find-package "SB-POSIX") (ignore-errors (require "SB-POSIX"))))

(defun save-account (acct path)
  (let ((tmp (concatenate 'string (namestring path) ".tmp")))
    (ensure-directories-exist path)
    ;; create the temporary file empty and private before any secret is written
    (with-open-file (out tmp :direction :output :if-exists :supersede) (declare (ignorable out)))
    (chmod-private tmp)
    ;; :overwrite keeps the (private) file we just made rather than replacing it
    (with-open-file (out tmp :direction :output :if-exists :overwrite :external-format :utf-8)
      (with-standard-io-syntax
        (let ((*package* (find-package '#:cl-marmot))
              (*print-readably* nil)
              (*print-pretty* nil))
          (prin1 (account->sexp acct) out)
          (terpri out))))
    (rename-file tmp path)
    path))

(defun load-account (path)
  (with-open-file (in path :external-format :utf-8)
    (with-standard-io-syntax
      (let ((*package* (find-package '#:cl-marmot))
            (*read-eval* nil))
        (sexp->account (read in))))))

;;; ---------------------------------------------------------------------------
;;; One process per account
;;;
;;; Two processes that each load the account, send, and save would each start
;;; from the same secret-tree state and encrypt under the same MLS ratchet
;;; generation: key and nonce reuse.  So every command that loads an account
;;; holds an exclusive lock file for its whole run.  The file records the
;;; holder's pid; a lock whose process no longer exists (checked through /proc
;;; where there is one) is stale and is taken over.

(defun %pid ()
  (let ((f (or (%ext-fn "SB-POSIX" "GETPID") (%ext-fn "SB-UNIX" "UNIX-GETPID"))))
    (and f (ignore-errors (funcall f)))))

(defun %pid-alive-p (pid)
  "T, NIL, or :UNKNOWN when this system cannot tell."
  (cond ((not (integerp pid)) :unknown)
        ((not (probe-file "/proc/self/")) :unknown)
        (t (and (probe-file (format nil "/proc/~D/" pid)) t))))

(defun %try-create-lock (lock-path)
  (with-open-file (out lock-path :direction :output :if-exists nil :if-does-not-exist :create)
    (when out
      (format out "~D ~D~%" (or (%pid) 0) (unix-time))
      t)))

(defun acquire-account-lock (account-path)
  "Take the account's lock file; returns its path.  Signals ACCOUNT-IN-USE if a
live process holds it."
  (let ((lock (concatenate 'string (namestring account-path) ".lock")))
    (ensure-directories-exist lock)
    (unless (%try-create-lock lock)
      (let* ((holder (ignore-errors (with-open-file (in lock) (read in nil nil))))
             (alive (%pid-alive-p holder)))
        (unless (and (null alive) (ignore-errors (delete-file lock)) (%try-create-lock lock))
          (error 'account-in-use :lock lock :pid (and (integerp holder) (plusp holder) holder)))))
    lock))

(defun release-account-lock (lock) (ignore-errors (delete-file lock)))

(define-condition account-in-use (marmot-error)
  ((lock :initarg :lock :reader account-in-use-lock)
   (pid :initarg :pid :initform nil :reader account-in-use-pid))
  (:report (lambda (c s)
             (format s "the account is in use by another marmot process~@[ (pid ~D)~]; ~
                        if that is wrong, remove ~A" (account-in-use-pid c) (account-in-use-lock c)))))

(defun call-with-account-lock (account-path fn)
  (let ((lock (acquire-account-lock account-path)))
    (unwind-protect (funcall fn)
      (release-account-lock lock))))

(defmacro with-account-lock ((account-path) &body body)
  `(call-with-account-lock ,account-path (lambda () ,@body)))
