;;;; api.lisp — the public Lisp API: package MARMOT
;;;;
;;;; An application opens an account, works with chats, and receives events:
;;;;
;;;;   (marmot:with-account (c)                         ; $MARMOT_HOME or ~/.local/share/cl-marmot/
;;;;     (marmot:add-handler c (lambda (e)
;;;;                             (when (eq (marmot:event-type e) :message)
;;;;                               (print (marmot:message-content (marmot:event-message e))))))
;;;;     (let ((chat (marmot:create-chat c '("alice@example.com") :name "lunch")))
;;;;       (marmot:send c chat "noon?"))
;;;;     (marmot:start c)                               ; background sync + the CLI socket
;;;;     ...)
;;;;
;;;; A CLIENT owns its account for as long as it is open: the account's lock
;;;; file keeps every other process out, and an in-process recursive lock
;;;; serialises the application's threads, the background sync thread and CLI
;;;; requests arriving on the socket.  Every operation that changes state saves
;;;; the account before it returns.  Event handlers run after the lock is
;;;; released, so a handler may call back into the API.

(defpackage #:marmot
  (:use #:common-lisp)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:import-from #:cl-marmot #:marmot-error #:account-in-use)
  (:export
   ;; accounts
   #:client #:default-home #:create-account #:open-account #:close-account #:with-account
   #:npub #:pubkey #:relays #:publish-key-package
   ;; chats
   #:chats #:find-chat #:chat-id #:chat-name #:chat-description #:chat-members #:chat-admins
   #:chat-epoch #:chat-active-p #:chat-leaving-p #:chat-messages
   ;; messages
   #:message #:message-id #:message-chat-id #:message-sender #:message-kind #:message-content
   #:message-tags #:message-created-at #:message-epoch #:message-own-p
   ;; actions
   #:create-chat #:send #:invite #:remove-members #:rename #:promote #:demote #:leave #:self-update
   ;; sync and events
   #:sync #:start #:stop #:running-p
   #:add-handler #:remove-handler
   #:event #:event-type #:event-chat #:event-message #:event-account #:event-detail
   ;; the CLI socket and entry point
   #:socket-path #:serve #:stop-serving #:run-command #:cli-main
   ;; conditions
   #:marmot-error #:account-in-use))

(in-package #:marmot)

;;; ---------------------------------------------------------------------------
;;; Client

(defstruct (client (:constructor %make-client))
  account home lock-file
  (lock (bt:make-recursive-lock "marmot client"))
  (handlers '())
  sync-thread (stop-requested nil) (interval 2)
  server-thread server-socket)

(defun default-home ()
  "$MARMOT_HOME, or ~/.local/share/cl-marmot/."
  (let ((env (cl-marmot::getenv "MARMOT_HOME")))
    (if (and env (plusp (length env)))
        (concatenate 'string (string-right-trim "/" env) "/")
        (concatenate 'string (or (cl-marmot::getenv "HOME") ".") "/.local/share/cl-marmot/"))))

(defun %account-path (home) (concatenate 'string home "account.sexp"))
(defun socket-path (&optional (home (default-home))) (concatenate 'string home "marmot.sock"))

(defmacro %locked ((client) &body body)
  `(bt:with-recursive-lock-held ((client-lock ,client)) ,@body))

(defun %save (client)
  (cl-marmot::save-account (client-account client) (%account-path (client-home client))))

(defun %open (home make-account)
  (let* ((home (concatenate 'string (string-right-trim "/" home) "/"))
         (lock (cl-marmot::acquire-account-lock (%account-path home))))
    (handler-bind ((error (lambda (c) (declare (ignore c)) (cl-marmot::release-account-lock lock))))
      ;; holding the lock proves nobody is serving: a socket file here is a leftover
      (when (probe-file (socket-path home)) (ignore-errors (delete-file (socket-path home))))
      (let ((client (%make-client :account (funcall make-account home) :home home :lock-file lock)))
        (setf (cl-marmot::account-on-event (client-account client)) nil)
        client))))

(defun create-account (&key (home (default-home)) relays name nsec)
  "Create a new account in HOME and publish its relay lists, profile name and a
KeyPackage to RELAYS.  NSEC imports an existing key.  Returns an open CLIENT."
  (when (probe-file (%account-path (concatenate 'string (string-right-trim "/" home) "/")))
    (error 'marmot-error :message (format nil "an account already exists in ~A" home)))
  (unless relays (error 'marmot-error :message "an account needs at least one relay"))
  (let ((client (%open home (lambda (h) (declare (ignore h))
                              (if nsec
                                  (cl-marmot::make-account-from-secret (cl-marmot::nsec-decode nsec) :relays relays)
                                  (cl-marmot::new-account :relays relays))))))
    (%locked (client)
      (cl-marmot::setup-account (client-account client) :name name)
      (%save client))
    client))

(defun open-account (&optional (home (default-home)))
  "Open the account in HOME.  Signals ACCOUNT-IN-USE if another process has it."
  (%open home (lambda (h)
                (unless (probe-file (%account-path h))
                  (error 'marmot-error :message (format nil "no account in ~A" h)))
                (cl-marmot::load-account (%account-path h)))))

(defun close-account (client)
  "Stop background work, save, close relay connections and release the account."
  (stop client)
  (stop-serving client)
  (%locked (client)
    (%save client)
    (cl-marmot::close-account-pools (client-account client)))
  (cl-marmot::release-account-lock (client-lock-file client))
  nil)

(defmacro with-account ((var &optional (home '(default-home))) &body body)
  `(let ((,var (open-account ,home)))
     (unwind-protect (progn ,@body)
       (close-account ,var))))

(defun npub (client) (cl-marmot::account-npub (client-account client)))
(defun pubkey (client) (cl-marmot::account-pubkey-hex (client-account client)))
(defun relays (client) (cl-marmot::account-relays (client-account client)))

(defun publish-key-package (client)
  (%locked (client)
    (prog1 (getf (cl-marmot::publish-key-package (client-account client)) :event-id)
      (%save client))))

;;; ---------------------------------------------------------------------------
;;; Chats (a chat is a Marmot group; the object is stable across epochs)

(defun chats (client)
  (%locked (client)
    (loop for g being the hash-values of (cl-marmot::account-groups (client-account client)) collect g)))

(defun find-chat (client designator)
  "By MLS group id (hex, or a unique prefix of it), Nostr group id, or name."
  (if (typep designator 'cl-marmot::marmot-group)
      designator
      (%locked (client) (cl-marmot::account-group (client-account client) designator))))

(defun %chat (client designator)
  (or (find-chat client designator)
      (error 'marmot-error :message (format nil "no chat ~S" designator))))

(defun chat-id (chat) (cl-marmot::mg-id-hex chat))
(defun chat-name (chat) (cl-marmot::mg-name chat))
(defun chat-description (chat)
  (or (nth-value 1 (cl-marmot::group-profile (cl-marmot::marmot-group-mls chat))) ""))
(defun chat-members (chat)
  "Hex pubkeys of the member accounts."
  (mapcar #'cl-marmot::octets->hex (cl-marmot::group-member-accounts (cl-marmot::marmot-group-mls chat))))
(defun chat-admins (chat)
  (mapcar #'cl-marmot::octets->hex (cl-marmot::group-admins (cl-marmot::marmot-group-mls chat))))
(defun chat-epoch (chat) (cl-marmot::mg-epoch chat))
(defun chat-active-p (chat) (and (cl-marmot::mls-group-active (cl-marmot::marmot-group-mls chat)) t))
(defun chat-leaving-p (chat) (and (cl-marmot::marmot-group-leaving chat) t))

;;; Messages

(defstruct (message (:constructor %make-message))
  id chat-id sender kind content tags created-at epoch own-p)

(defun %message (chat plist)
  (%make-message :id (getf plist :id) :chat-id (chat-id chat) :sender (getf plist :sender)
                 :kind (getf plist :kind) :content (getf plist :content) :tags (getf plist :tags)
                 :created-at (getf plist :created-at) :epoch (getf plist :epoch)
                 :own-p (and (getf plist :own) t)))

(defun chat-messages (chat &key limit)
  "Delivered messages, oldest first (the newest LIMIT if given)."
  (let ((all (cl-marmot::marmot-group-messages chat)))
    (mapcar (lambda (p) (%message chat p))
            (reverse (if limit (subseq all 0 (min limit (length all))) all)))))

;;; ---------------------------------------------------------------------------
;;; Events

(defstruct (event (:constructor %make-event))
  type          ; :message :joined :member-added :member-removed :renamed :removed :epoch :rejected
  chat          ; the chat object
  message       ; a MESSAGE, for :message
  account       ; hex pubkey, for :member-added / :member-removed
  detail)       ; the remaining protocol details, as a plist

(defun %event (chat r)
  (let ((type (getf r :type)))
    (unless (member type '(:duplicate :undecryptable :stale :own-commit-echo :proposal))
      (%make-event :type type :chat chat
                   :message (and (eq type :message) (%message chat r))
                   :account (let ((a (getf r :account))) (and a (cl-marmot::octets->hex a)))
                   :detail r))))

(defun add-handler (client fn)
  "Call FN with each EVENT.  Handlers run on whichever thread synced (the
background thread after START), outside the client lock."
  (%locked (client) (pushnew fn (client-handlers client)))
  fn)

(defun remove-handler (client fn)
  (%locked (client) (setf (client-handlers client) (remove fn (client-handlers client)))))

(defun %dispatch (client events)
  (let ((handlers (%locked (client) (copy-list (client-handlers client)))))
    (dolist (e events)
      (dolist (h handlers)
        (handler-case (funcall h e)
          (error (c) (format *error-output* "~&marmot: event handler failed: ~A~%" c)))))))

(defun sync (client)
  "Fetch and process everything new; returns the events (also given to the handlers)."
  (let ((events '()))
    (%locked (client)
      (let ((acct (client-account client)))
        (setf (cl-marmot::account-on-event acct)
              (lambda (a mg r) (declare (ignore a))
                (let ((e (%event mg r))) (when e (push e events)))))
        (unwind-protect (cl-marmot::sync acct)
          (setf (cl-marmot::account-on-event acct) nil))
        (%save client)))
    (setf events (nreverse events))
    (%dispatch client events)
    events))

(defun start (client &key (interval 2) (serve t))
  "Sync every INTERVAL seconds on a background thread; with SERVE, also accept
CLI commands on the account's socket."
  (%locked (client)
    (unless (client-sync-thread client)
      (setf (client-interval client) interval
            (client-stop-requested client) nil
            (client-sync-thread client)
            (bt:make-thread
             (lambda ()
               (loop until (client-stop-requested client)
                     do (handler-case (sync client)
                          (error (c) (format *error-output* "~&marmot: sync failed: ~A~%" c)))
                        (loop repeat (* 10 (client-interval client))
                              until (client-stop-requested client)
                              do (sleep 1/10))))
             :name "marmot sync"))))
  (when serve (serve client))
  client)

(defun stop (client)
  (let ((thread (%locked (client) (client-sync-thread client))))
    (when thread
      (setf (client-stop-requested client) t)
      (bt:join-thread thread)
      (%locked (client) (setf (client-sync-thread client) nil))))
  client)

(defun running-p (client) (and (client-sync-thread client) t))

;;; ---------------------------------------------------------------------------
;;; Actions.  Each syncs first (so it acts on the newest epoch), then saves.

(defmacro %action ((client) &body body)
  `(%locked (,client)
     (let ((acct (client-account ,client)))
       (declare (ignorable acct))
       (cl-marmot::sync acct)
       (multiple-value-prog1 (progn ,@body)
         (%save ,client)))))

(defun create-chat (client invitees &key (name "") (description ""))
  "Create a chat with INVITEES (npubs, hex pubkeys or NIP-05 addresses).  An
empty NAME is how a one-to-one conversation is usually presented."
  (%action (client) (cl-marmot::create-group-with acct name invitees :description description)))

(defun send (client chat text &key (kind 9) tags)
  "Send TEXT (a kind 9 chat message unless KIND says otherwise).  Returns the MESSAGE."
  (%action (client)
    (let ((chat (%chat client chat)))
      (cl-marmot::send-message acct chat text :kind kind :tags tags)
      (%message chat (first (cl-marmot::marmot-group-messages chat))))))

(defun invite (client chat invitees)
  (%action (client) (cl-marmot::invite acct (%chat client chat) invitees) (%chat client chat)))

(defun remove-members (client chat members)
  (%action (client) (cl-marmot::remove-members acct (%chat client chat) members) (%chat client chat)))

(defun rename (client chat name &key description)
  (%action (client)
    (let ((chat (%chat client chat)))
      (if description
          (cl-marmot::rename-group acct chat name description)
          (cl-marmot::rename-group acct chat name))
      chat)))

(defun promote (client chat member)
  (%action (client) (cl-marmot::promote acct (%chat client chat) member) (%chat client chat)))

(defun demote (client chat member)
  (%action (client) (cl-marmot::demote acct (%chat client chat) member) (%chat client chat)))

(defun leave (client chat)
  "Ask to leave CHAT (a SelfRemove proposal another member commits)."
  (%action (client) (cl-marmot::leave-group acct (%chat client chat)) (%chat client chat)))

(defun self-update (client chat)
  (%action (client) (cl-marmot::self-update acct (%chat client chat)) (%chat client chat)))
