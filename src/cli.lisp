;;;; cli.lisp — the `marmot` command line, a client of the public API
;;;;
;;;; Whichever process holds an account — `marmot daemon`, `marmot watch`, or an
;;;; application that called MARMOT:START — also listens on $MARMOT_HOME/marmot.sock.
;;;; A `marmot` command that finds that socket forwards its arguments there and
;;;; prints the reply, so it runs inside the process that owns the account
;;;; instead of failing on the account lock.  Both paths run RUN-COMMAND.

(in-package #:marmot)

(defparameter *usage* "usage:
  marmot init [--relay URL]... [--name NAME] [--nsec NSEC]
  marmot daemon                      hold the account: sync in the background and
                                     serve the other commands over a socket
  marmot watch [SECONDS]             like daemon, printing what arrives
  marmot whoami | sync | chats | keypackage
  marmot create NAME [WHO...]        marmot invite CHAT WHO...
  marmot send CHAT TEXT...           marmot messages CHAT [N]
  marmot members CHAT                marmot rename CHAT NAME
  marmot remove CHAT WHO...          marmot self-update CHAT
  marmot promote CHAT WHO            marmot demote CHAT WHO
  marmot leave CHAT
WHO is an npub, a hex pubkey or a NIP-05 address (name@domain).
CHAT is a chat id, a unique prefix of one, or a chat name.
State: $MARMOT_HOME/account.sexp (default ~/.local/share/cl-marmot/)
")

(defun %out (fmt &rest args) (apply #'format t fmt args) (finish-output))

(defun %short (s) (subseq s 0 (min 12 (length s))))
(defun %npub (hex) (cl-marmot::npub-encode (cl-marmot::hex->octets hex)))
(defun %label (chat) (if (plusp (length (chat-name chat))) (chat-name chat) (%short (chat-id chat))))

(defun %print-message (chat m)
  (%out "[~A] ~A: ~A~%" (%label chat) (%short (%npub (message-sender m)))
        (if (eql (message-kind m) 9)
            (message-content m)
            (format nil "(kind ~D) ~A" (message-kind m) (message-content m)))))

(defun %print-event (e)
  (let ((chat (event-chat e)))
    (case (event-type e)
      (:message (%print-message chat (event-message e)))
      (:joined (%out "[~A] joined (epoch ~D)~%" (%label chat) (chat-epoch chat)))
      (:epoch (%out "[~A] epoch ~D~%" (%label chat) (getf (event-detail e) :epoch)))
      (:member-added (%out "[~A] + ~A~%" (%label chat) (%npub (event-account e))))
      (:member-removed (%out "[~A] - ~A~%" (%label chat) (%npub (event-account e))))
      (:renamed (%out "[~A] renamed to ~S~%" (%label chat) (getf (event-detail e) :name)))
      (:removed (%out "[~A] you were removed~%" (%label chat)))
      (:pending-superseded (%out "[~A] another member's commit took epoch ~D; ours was dropped~@[ (re-invite ~{~A~^, ~})~]~%"
                                 (%label chat) (getf (event-detail e) :epoch)
                                 (mapcar #'%npub (getf (event-detail e) :invitees))))
      (:rejected (%out "[~A] rejected input: ~A~%" (%label chat) (getf (event-detail e) :reason)))
      (t (%out "[~A] ~S~%" (%label chat) (event-detail e))))))

(defun %parse-flags (args)
  "Split ARGS into (values flag-alist positional)."
  (let ((flags '()) (pos '()))
    (loop while args
          do (let ((a (pop args)))
               (if (and (> (length a) 2) (string= "--" a :end2 2))
                   (push (cons (subseq a 2) (pop args)) flags)
                   (push a pos))))
    (values (nreverse flags) (nreverse pos))))

(defun %text (words) (format nil "~{~A~^ ~}" words))

;;; ---------------------------------------------------------------------------
;;; Commands that run against an open client (locally or inside the daemon)

(defun run-command (client cmd args)
  "Run one CLI command against CLIENT, printing to *STANDARD-OUTPUT*.  Returns
the exit code."
  (flet ((chat () (or (and (first args) (find-chat client (first args)))
                      (error 'marmot-error :message (format nil "no chat ~S" (first args))))))
    (cond
      ((string= cmd "whoami") (%out "~A~%~A~%relays: ~{~A~^ ~}~%" (npub client) (pubkey client) (relays client)))
      ((string= cmd "keypackage") (%out "published ~A~%" (publish-key-package client)))
      ((string= cmd "sync") (mapc #'%print-event (sync client)))
      ((member cmd '("chats" "groups") :test #'string=)
       (sync client)
       (dolist (c (chats client))
         (%out "~A  epoch ~3D  ~2D members  ~8A  ~A~%" (chat-id c) (chat-epoch c) (length (chat-members c))
               (cond ((not (chat-active-p c)) "removed") ((chat-leaving-p c) "leaving") (t "active"))
               (chat-name c))))
      ((string= cmd "create") (%out "created ~A~%" (chat-id (create-chat client (rest args) :name (or (first args) "")))))
      ((string= cmd "invite") (invite client (chat) (rest args)) (%out "invited~%"))
      ((string= cmd "remove") (remove-members client (chat) (rest args)) (%out "removed~%"))
      ((string= cmd "rename") (rename client (chat) (%text (rest args))) (%out "renamed~%"))
      ((string= cmd "promote") (promote client (chat) (second args)) (%out "promoted~%"))
      ((string= cmd "demote") (demote client (chat) (second args)) (%out "demoted~%"))
      ((string= cmd "leave") (leave client (chat)) (%out "leave requested~%"))
      ((string= cmd "self-update") (self-update client (chat)) (%out "epoch ~D~%" (chat-epoch (chat))))
      ((string= cmd "send") (send client (chat) (%text (rest args))) (%out "sent~%"))
      ((string= cmd "messages")
       (sync client)
       (let ((c (chat)))
         (dolist (m (chat-messages c :limit (if (second args) (parse-integer (second args)) 20)))
           (%print-message c m))))
      ((string= cmd "members")
       (sync client)
       (let ((c (chat)))
         (dolist (m (chat-members c))
           (%out "~A~:[~; (admin)~]~:[~; (you)~]~%" (%npub m)
                 (member m (chat-admins c) :test #'string=) (string= m (pubkey client))))))
      (t (error 'marmot-error :message (format nil "unknown command ~S (try `marmot help`)" cmd))))
    0))

;;; ---------------------------------------------------------------------------
;;; The socket.  One request per connection: a JSON array of strings (the
;;; arguments) on one line; the reply is {"code":N,"output":"..."}.

(defun %sock (name &rest args) (apply #'cl-marmot::%call "SB-BSD-SOCKETS" name args))

(defun %make-local-socket ()
  (make-instance (cl-marmot::%sym "SB-BSD-SOCKETS" "LOCAL-SOCKET") :type :stream))

(defun %socket-stream (socket)
  (%sock "SOCKET-MAKE-STREAM" socket :input t :output t :element-type 'character
                                     :external-format :utf-8 :buffering :full))

(defun %handle-request (client stream)
  (let* ((line (read-line stream nil nil))
         (argv (and line (ignore-errors (coerce (cl-marmot::parse-json line) 'list))))
         (code 1)
         (output (with-output-to-string (*standard-output*)
                   (cond ((not (and argv (every #'stringp argv))) (%out "error: bad request~%"))
                         ((member (first argv) '("init" "daemon" "watch") :test #'string=)
                          (%out "error: marmot is already running for this account~%"))
                         (t (setf code (handler-case (%locked (client) (run-command client (first argv) (rest argv)))
                                         (error (c) (%out "error: ~A~%" c) 1))))))))
    (write-line (cl-marmot::to-json (cl-marmot::jobj "code" code "output" output)) stream)
    (force-output stream)))

(defun serve (client)
  "Accept CLI commands on the account's socket (owner-only permissions)."
  (unless (client-server-thread client)
    (let ((path (socket-path (client-home client)))
          (socket (%make-local-socket)))
      ;; we hold the account lock, so any socket file here is a leftover
      (when (probe-file path) (ignore-errors (delete-file path)))
      (%sock "SOCKET-BIND" socket path)
      (cl-marmot::chmod-private path)
      (%sock "SOCKET-LISTEN" socket 8)
      (setf (client-server-socket client) socket
            (client-server-thread client)
            (bt:make-thread
             (lambda ()
               (loop
                 (let ((conn (handler-case (%sock "SOCKET-ACCEPT" socket) (error () (return)))))
                   (when conn
                     (handler-case (let ((s (%socket-stream conn)))
                                     (unwind-protect (%handle-request client s)
                                       (ignore-errors (close s))))
                       (error (c) (format *error-output* "~&marmot: socket request failed: ~A~%" c)))
                     (ignore-errors (%sock "SOCKET-CLOSE" conn))))))
             :name "marmot socket"))))
  client)

(defun stop-serving (client)
  (let ((socket (client-server-socket client)) (thread (client-server-thread client)))
    (when socket
      (ignore-errors (%sock "SOCKET-CLOSE" socket))
      (when thread (ignore-errors (bt:join-thread thread)))
      (ignore-errors (delete-file (socket-path (client-home client))))
      (setf (client-server-socket client) nil (client-server-thread client) nil)))
  client)

(defun %forward (home argv)
  "Send ARGV to the process serving HOME.  Returns the exit code, or NIL when
nothing is listening."
  (let ((path (socket-path home)))
    (when (probe-file path)
      (let ((socket (%make-local-socket)))
        (when (handler-case (progn (%sock "SOCKET-CONNECT" socket path) t)
                (error () (ignore-errors (%sock "SOCKET-CLOSE" socket)) nil))
          (let ((s (%socket-stream socket)))
            (unwind-protect
                 (progn (write-line (cl-marmot::to-json (coerce argv 'simple-vector)) s)
                        (force-output s)
                        (let* ((reply (cl-marmot::parse-json (read-line s)))
                               (output (cl-marmot::jget reply "output")))
                          (write-string output) (finish-output)
                          (cl-marmot::jget reply "code")))
              (ignore-errors (close s))
              (ignore-errors (%sock "SOCKET-CLOSE" socket)))))))))

;;; ---------------------------------------------------------------------------
;;; Entry point

(defun cli-main (args)
  (handler-case (%cli args)
    (error (c) (%out "error: ~A~%" c) 1)))

(defun %hold (client seconds print)
  "Run as the account's owner: background sync + socket, until SECONDS pass (or forever)."
  (when print (add-handler client #'%print-event))
  (start client :serve t)
  (if seconds
      (sleep seconds)
      (loop (sleep 3600)))
  0)

(defun %cli (args)
  (let ((cmd (first args)) (rest (rest args)) (home (default-home)))
    (cond
      ((or (null cmd) (member cmd '("help" "-h" "--help") :test #'string=)) (%out "~A" *usage*) 0)
      ((string= cmd "init")
       (multiple-value-bind (flags) (%parse-flags rest)
         (let ((client (create-account :home home
                                       :relays (mapcar #'cdr (remove "relay" flags :key #'car :test-not #'string=))
                                       :name (cdr (assoc "name" flags :test #'string=))
                                       :nsec (cdr (assoc "nsec" flags :test #'string=)))))
           (%out "~A~%" (npub client))
           (close-account client)
           0)))
      ((and (not (member cmd '("daemon" "watch") :test #'string=)) (%forward home args)))
      (t
       (let ((client (open-account home)))
         (unwind-protect
              (cond ((string= cmd "daemon") (%hold client nil nil))
                    ((string= cmd "watch") (%hold client (if rest (parse-integer (first rest)) nil) t))
                    (t (run-command client cmd rest)))
           (close-account client)))))))
