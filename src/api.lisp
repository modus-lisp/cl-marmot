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
   #:message-tags #:message-created-at #:message-epoch #:message-own-p #:message-invalidated-p
   #:message-edited-p #:message-reply-to #:message-reactions
   ;; people
   #:profile #:display-name
   ;; actions
   #:create-chat #:send #:invite #:remove-members #:rename #:promote #:demote #:leave #:self-update
   ;; sync and events
   #:sync #:start #:stop #:running-p
   #:add-handler #:remove-handler
   #:event #:event-type #:event-chat #:event-message #:event-account #:event-epoch #:event-name
   #:event-reason #:event-commit #:event-message-id #:event-target-id #:event-invitees
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
(defun socket-path (&optional (home (default-home)))
  "Where the process holding the account in HOME listens for CLI commands."
  (concatenate 'string home "marmot.sock"))

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
        (setf (cl-marmot::account-on-event (client-account client)) nil
              ;; commits and Welcomes are saved before they are published
              (cl-marmot::account-checkpoint (client-account client)) (lambda () (%save client)))
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
  "Run BODY with VAR bound to the open account in HOME, closing it afterwards."
  `(let ((,var (open-account ,home)))
     (unwind-protect (progn ,@body)
       (close-account ,var))))

(defun npub (client)
  "This account's public key as an npub."
  (cl-marmot::account-npub (client-account client)))
(defun pubkey (client)
  "This account's public key, hex."
  (cl-marmot::account-pubkey-hex (client-account client)))
(defun relays (client)
  "The relays this account publishes to and reads its inbox from."
  (cl-marmot::account-relays (client-account client)))

(defun publish-key-package (client)
  "Publish a fresh KeyPackage (others need one to invite us).  Returns its event id."
  (%locked (client)
    (prog1 (getf (cl-marmot::publish-key-package (client-account client)) :event-id)
      (%save client))))

;;; ---------------------------------------------------------------------------
;;; Chats (a chat is a Marmot group; the object is stable across epochs)

(defun chats (client)
  "Every chat of this account, including ones we have left or were removed from."
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

(defun chat-id (chat)
  "The chat's MLS group id, hex."
  (cl-marmot::mg-id-hex chat))
(defun chat-name (chat)
  "The chat's name (\"\" for an unnamed, usually one-to-one, chat)."
  (cl-marmot::mg-name chat))
(defun chat-description (chat)
  "The chat's description, or \"\"."
  (or (nth-value 1 (cl-marmot::group-profile (cl-marmot::marmot-group-mls chat))) ""))
(defun chat-members (chat)
  "Hex pubkeys of the member accounts."
  (mapcar #'cl-marmot::octets->hex (cl-marmot::group-member-accounts (cl-marmot::marmot-group-mls chat))))
(defun chat-admins (chat)
  "Hex pubkeys of the chat's admins."
  (mapcar #'cl-marmot::octets->hex (cl-marmot::group-admins (cl-marmot::marmot-group-mls chat))))
(defun chat-epoch (chat)
  "The chat's current MLS epoch."
  (cl-marmot::mg-epoch chat))
(defun chat-active-p (chat)
  "False once we have been removed (or our leave was committed)."
  (and (cl-marmot::mls-group-active (cl-marmot::marmot-group-mls chat)) t))
(defun chat-leaving-p (chat)
  "True after LEAVE, until another member commits our departure."
  (and (cl-marmot::marmot-group-leaving chat) t))

;;; Messages
;;;
;;; A chat's history is its kind 9 messages.  Edits (kind 1009, from the
;;; message's own author) are applied to the message they name; reactions
;;; (kind 7) are attached to theirs.  Push-notification bookkeeping (kinds
;;; 446-451) and group system rows (kind 1210, which clients derive from group
;;; state instead) are not messages.  Other kinds are kept and available
;;; with :KINDS :ALL.

(defparameter +hidden-kinds+ '(446 447 448 449 450 451 1210))

(defstruct (message (:constructor %make-message))
  "A message in a chat."
  id            ; hex id of the app event
  chat-id       ; hex id of its chat
  sender        ; hex pubkey of the author's account
  kind          ; 9 for chat messages
  content       ; text (the latest edit, for an edited message)
  tags          ; the app event's tags: list of lists of strings
  created-at    ; Unix seconds, as the author stated it
  epoch         ; MLS epoch it was sent in
  own-p         ; sent by this account
  invalidated-p ; delivered on a branch that later lost convergence
  edited-p      ; CONTENT comes from an edit
  reply-to      ; hex id of the message this replies to, if any
  reactions)    ; list of (sender-hex . reaction-content)

(defun %tag-values (tags name) (mapcar #'second (remove-if-not (lambda (tg) (equal (first tg) name)) tags)))

(defun %message (chat plist)
  (%make-message :id (getf plist :id) :chat-id (chat-id chat) :sender (getf plist :sender)
                 :kind (getf plist :kind) :content (getf plist :content) :tags (getf plist :tags)
                 :created-at (getf plist :created-at) :epoch (getf plist :epoch)
                 :own-p (and (getf plist :own) t)
                 :invalidated-p (and (getf plist :invalidated) t)
                 :reply-to (and (eql (getf plist :kind) 9) (first (%tag-values (getf plist :tags) "e")))))

(defun chat-messages (chat &key limit (kinds '(9)) include-invalidated)
  "Messages, oldest first (the newest LIMIT if given).  KINDS is a list of app
event kinds, or :ALL for everything that is not bookkeeping.  Edits and
reactions are applied to the messages they target.  Messages withdrawn
because their branch lost convergence are left out unless INCLUDE-INVALIDATED."
  (let* ((plists (reverse (remove-if (lambda (p) (and (getf p :invalidated) (not include-invalidated)))
                                     (cl-marmot::marmot-group-messages chat))))
         (msgs (loop for p in plists
                     unless (or (member (getf p :kind) '(7 1009)) (member (getf p :kind) +hidden-kinds+)
                                (and (listp kinds) (not (member (getf p :kind) kinds))))
                       collect (%message chat p)))
         (by-id (make-hash-table :test #'equal)))
    (dolist (m msgs) (setf (gethash (message-id m) by-id) m))
    ;; edits: only the original author's count; the newest wins
    (let ((latest (make-hash-table :test #'equal)))
      (dolist (p plists)
        (when (eql (getf p :kind) 1009)
          (let* ((target (first (%tag-values (getf p :tags) "e")))
                 (m (and target (gethash target by-id))))
            (when (and m (equal (getf p :sender) (message-sender m))
                       (>= (getf p :created-at) (gethash target latest 0)))
              (setf (gethash target latest) (getf p :created-at)
                    (message-content m) (getf p :content)
                    (message-edited-p m) t))))))
    ;; reactions: NIP-25, the last e tag names the target
    (dolist (p plists)
      (when (eql (getf p :kind) 7)
        (let ((m (gethash (car (last (%tag-values (getf p :tags) "e"))) by-id)))
          (when m (setf (message-reactions m)
                        (append (message-reactions m) (list (cons (getf p :sender) (getf p :content)))))))))
    (if limit (last msgs limit) msgs)))

;;; ---------------------------------------------------------------------------
;;; Events

(defstruct (event (:constructor %make-event))
  "Something that happened in a chat.  TYPE is one of
  :message :edit :reaction :app-event   a message arrived (EVENT-MESSAGE); for
                                        :edit and :reaction, EVENT-TARGET-ID names its target
  :joined                               we joined this chat
  :member-added :member-removed         EVENT-ACCOUNT joined or left
  :renamed                              EVENT-NAME is the new name
  :epoch                                the group advanced to EVENT-EPOCH
  :removed                              we are no longer a member
  :pending-superseded                   another member's commit took the epoch ours was for;
                                        EVENT-INVITEES were not added and need re-inviting
  :commit-invalidated                   a change we had applied lost convergence (EVENT-COMMIT)
  :message-invalidated                  a message we had delivered was on that branch
                                        (EVENT-MESSAGE-ID)
  :rejected                             input we could not accept (EVENT-REASON)"
  type chat message account epoch name reason commit message-id target-id invitees)

(defun %event (chat r)
  (let ((type (getf r :type)))
    (unless (member type '(:duplicate :undecryptable :stale :own-commit-merged :proposal :held))
      (let ((msg (and (eq type :message) (%message chat r))))
        (when (and msg (member (message-kind msg) +hidden-kinds+))
          (return-from %event nil))
        (%make-event :type (if msg
                               (case (message-kind msg) (9 :message) (1009 :edit) (7 :reaction) (t :app-event))
                               type)
                     :chat chat :message msg
                     :account (let ((a (getf r :account))) (and a (cl-marmot::octets->hex a)))
                     :epoch (getf r :epoch) :name (and (eq type :renamed) (getf r :name))
                     :reason (getf r :reason) :commit (getf r :commit)
                     :message-id (and (eq type :message-invalidated) (getf r :id))
                     :target-id (and msg (member (message-kind msg) '(7 1009))
                                     (car (last (%tag-values (message-tags msg) "e"))))
                     :invitees (getf r :invitees))))))

;;; Profiles (kind 0), for showing names instead of keys

(defun profile (client pubkey)
  "PUBKEY's published profile as a plist (:name :display-name :about :picture
:nip05), fetched from the directory relays and cached for a day; NIL if none."
  (%locked (client)
    (cl-marmot::account-profile (client-account client)
                                (cl-marmot::octets->hex (cl-marmot::parse-pubkey pubkey)))))

(defun display-name (client pubkey)
  "The best human name for PUBKEY: its display name, its name, or a short npub."
  (let ((p (ignore-errors (profile client pubkey))))
    (or (let ((d (getf p :display-name))) (and (stringp d) (plusp (length d)) d))
        (let ((n (getf p :name))) (and (stringp n) (plusp (length n)) n))
        (let ((npub (cl-marmot::npub-encode (cl-marmot::parse-pubkey pubkey))))
          (concatenate 'string (subseq npub 0 12) "…")))))

(defun add-handler (client fn)
  "Call FN with each EVENT.  Handlers run on whichever thread synced (the
background thread after START), outside the client lock."
  (%locked (client) (pushnew fn (client-handlers client)))
  fn)

(defun remove-handler (client fn)
  "Stop calling FN with events."
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
  "Stop the background sync thread started by START."
  (let ((thread (%locked (client) (client-sync-thread client))))
    (when thread
      (setf (client-stop-requested client) t)
      (bt:join-thread thread)
      (%locked (client) (setf (client-sync-thread client) nil))))
  client)

(defun running-p (client)
  "Is the background sync thread running?"
  (and (client-sync-thread client) t))

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
  "Add INVITEES (npubs, hex pubkeys or NIP-05 addresses) to CHAT; we must be an admin."
  (%action (client) (cl-marmot::invite acct (%chat client chat) invitees) (%chat client chat)))

(defun remove-members (client chat members)
  "Remove MEMBERS from CHAT; we must be an admin."
  (%action (client) (cl-marmot::remove-members acct (%chat client chat) members) (%chat client chat)))

(defun rename (client chat name &key description)
  "Rename CHAT (and set its DESCRIPTION if given); we must be an admin."
  (%action (client)
    (let ((chat (%chat client chat)))
      (if description
          (cl-marmot::rename-group acct chat name description)
          (cl-marmot::rename-group acct chat name))
      chat)))

(defun promote (client chat member)
  "Make MEMBER an admin of CHAT; we must be an admin."
  (%action (client) (cl-marmot::promote acct (%chat client chat) member) (%chat client chat)))

(defun demote (client chat member)
  "Take admin rights from MEMBER in CHAT; at least one admin must remain."
  (%action (client) (cl-marmot::demote acct (%chat client chat) member) (%chat client chat)))

(defun leave (client chat)
  "Ask to leave CHAT (a SelfRemove proposal another member commits)."
  (%action (client) (cl-marmot::leave-group acct (%chat client chat)) (%chat client chat)))

(defun self-update (client chat)
  "Rotate our keys in CHAT (forward secrecy and post-compromise security)."
  (%action (client) (cl-marmot::self-update acct (%chat client chat)) (%chat client chat)))

;;; Accessor documentation (the struct definitions carry it only as comments)

(loop for (name doc) on
      '(message-id "Hex id of the message's app event."
        message-chat-id "Hex id of the chat the message is in."
        message-sender "Hex pubkey of the account that wrote it."
        message-kind "Its app event kind (9 for chat messages)."
        message-content "Its text: the newest edit for an edited message."
        message-tags "Its app event tags, a list of lists of strings."
        message-created-at "Unix seconds, as its author stated."
        message-epoch "The MLS epoch it was sent in."
        message-own-p "Was it sent by this account?"
        message-invalidated-p "Was it delivered on a branch that later lost convergence?"
        message-edited-p "Does its content come from an edit?"
        message-reply-to "Hex id of the message it replies to, or NIL."
        message-reactions "Its reactions: a list of (sender-hex . content)."
        event-type "What happened; see the EVENT structure's documentation."
        event-chat "The chat it happened in."
        event-message "The MESSAGE, for :message, :edit, :reaction and :app-event."
        event-account "Hex pubkey, for :member-added and :member-removed."
        event-epoch "The epoch, for :epoch, :commit-invalidated and :pending-superseded."
        event-name "The new name, for :renamed."
        event-reason "Why, for :rejected."
        event-commit "Hex digest of the commit, for state events and :commit-invalidated."
        event-message-id "Hex id of the withdrawn message, for :message-invalidated."
        event-target-id "Hex id of the message an :edit or :reaction targets."
        event-invitees "Hex pubkeys that were not added, for :pending-superseded.")
      by #'cddr
      do (setf (documentation name 'function) doc))
