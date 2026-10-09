;;;; websocket.lisp — an RFC 6455 client over a CONN (plain TCP or TLS)
;;;;
;;;; Single-threaded and polling: WS-RECEIVE waits up to a timeout using the
;;;; connection's READY-P, so a client can service several relays from one loop
;;;; with no threads.  Client frames are masked; pings are answered; fragmented
;;;; messages are reassembled.
;;;;
;;;; The websocket runs over a CONN: four closures (read exactly N octets,
;;;; write octets, is input ready, close).  Plain TCP and TLS both provide one,
;;;; which keeps TLS out of this file and needs no Gray streams.

(in-package #:cl-marmot)

(define-condition websocket-error (error)
  ((message :initarg :message :reader websocket-error-message))
  (:report (lambda (c s) (format s "websocket: ~A" (websocket-error-message c)))))

(defun ws-fail (fmt &rest args)
  (error 'websocket-error :message (apply #'format nil fmt args)))

(defstruct conn
  read-fn                 ; (n) -> exactly N octets; signals on EOF
  write-fn                ; (octets) -> writes and flushes
  ready-fn                ; () -> true if a read would not block
  close-fn)               ; ()

(defun conn-read (c n) (funcall (conn-read-fn c) n))
(defun conn-write (c octets) (funcall (conn-write-fn c) octets))
(defun conn-ready-p (c) (funcall (conn-ready-fn c)))
(defun conn-close (c) (ignore-errors (funcall (conn-close-fn c))))

(defun tcp-conn (host port)
  "A CONN over a plain TCP connection."
  (multiple-value-bind (stream socket) (tcp-connect host port)
    (make-conn :read-fn (lambda (n)
                          (let* ((buf (make-octets n))
                                 (got (read-sequence buf stream)))
                            (unless (= got n) (ws-fail "connection closed"))
                            buf))
               :write-fn (lambda (octets) (write-sequence octets stream) (force-output stream))
               :ready-fn (lambda () (ignore-errors (listen stream)))
               :close-fn (lambda () (ignore-errors (close stream)) (tcp-close socket)))))

(defvar *tls-connect-function* nil
  "If non-NIL, (funcall it host port) => a CONN carrying TLS, for wss://.")

(defstruct ws
  url conn
  (open t)
  (fragments '())
  (fragment-opcode nil))

(defun parse-ws-url (url)
  "Returns (values secure host port path)."
  (let* ((secure (cond ((and (> (length url) 6) (string-equal "wss://" url :end2 6)) t)
                       ((and (> (length url) 5) (string-equal "ws://" url :end2 5)) nil)
                       (t (ws-fail "not a ws/wss URL: ~A" url))))
         (rest (subseq url (if secure 6 5)))
         (slash (position #\/ rest))
         (hostport (subseq rest 0 slash))
         (path (if slash (subseq rest slash) "/"))
         (colon (position #\: hostport :from-end t))
         (bracket (position #\] hostport)))
    (when (and colon bracket (< colon bracket)) (setf colon nil))
    (values secure
            (string-trim "[]" (if colon (subseq hostport 0 colon) hostport))
            (if colon (parse-integer hostport :start (1+ colon)) (if secure 443 80))
            path)))

(defun %ws-read-line (conn)
  "Read an HTTP header line (CRLF-terminated) as a string."
  (let ((buf (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop (let ((b (aref (conn-read conn 1) 0)))
            (when (and (= b 10) (plusp (fill-pointer buf)) (= (aref buf (1- (fill-pointer buf))) 13))
              (return (utf8->string (coerce-octets buf) :end (1- (fill-pointer buf)))))
            (vector-push-extend b buf)
            (when (> (fill-pointer buf) 8192) (ws-fail "handshake header too long"))))))

(defun ws-connect (url)
  (multiple-value-bind (secure host port path) (parse-ws-url url)
    (let ((conn (if secure
                    (if *tls-connect-function*
                        (funcall *tls-connect-function* host port)
                        (ws-fail "wss:// needs TLS, which this build does not provide (~A)" url))
                    (tcp-conn host port))))
      (let ((key (octets->base64 (random-octets 16))))
        (conn-write conn
                    (string->utf8
                          (format nil "GET ~A HTTP/1.1~C~CHost: ~A~:[:~D~;~*~]~C~CUpgrade: websocket~C~CConnection: Upgrade~C~CSec-WebSocket-Key: ~A~C~CSec-WebSocket-Version: 13~C~C~C~C"
                                  path #\Return #\Newline host (= port (if secure 443 80)) port
                                  #\Return #\Newline #\Return #\Newline #\Return #\Newline
                                  key #\Return #\Newline #\Return #\Newline #\Return #\Newline)))
        (let ((status (%ws-read-line conn))
              (accept nil))
          (unless (search " 101" status) (ws-fail "handshake refused: ~A" status))
          (loop for line = (%ws-read-line conn)
                until (string= line "")
                do (let ((colon (position #\: line)))
                     (when (and colon (string-equal (string-trim " " (subseq line 0 colon)) "sec-websocket-accept"))
                       (setf accept (string-trim " " (subseq line (1+ colon)))))))
          (unless (and accept
                       (string= accept (octets->base64
                                        (sha1 (string->utf8 (concatenate 'string key "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))))))
            (ws-fail "bad Sec-WebSocket-Accept")))
        (make-ws :url url :conn conn)))))

(defun %ws-send-frame (ws opcode payload)
  (let* ((n (length payload))
         (mask (random-octets 4))
         (header (with-writer (w)
                   (w-u8 w (logior #x80 opcode))
                   (cond ((< n 126) (w-u8 w (logior #x80 n)))
                         ((< n 65536) (w-u8 w (logior #x80 126)) (w-u16 w n))
                         (t (w-u8 w (logior #x80 127)) (w-u64 w n)))
                   (w-bytes w mask)))
         (masked (make-octets n)))
    (dotimes (i n) (setf (aref masked i) (logxor (aref payload i) (aref mask (logand i 3)))))
    (conn-write (ws-conn ws) (concat-octets header masked))))

(defun ws-send-text (ws string)
  (unless (ws-open ws) (ws-fail "connection is closed"))
  (%ws-send-frame ws 1 (string->utf8 string)))

(defun %ws-read-frame (ws)
  "Read one frame (blocking).  Returns (values opcode payload fin)."
  (let* ((c (ws-conn ws))
         (h (conn-read c 2))
         (fin (logbitp 7 (aref h 0)))
         (opcode (logand (aref h 0) #x0F))
         (masked (logbitp 7 (aref h 1)))
         (len (logand (aref h 1) #x7F)))
    (setf len (case len
                (126 (octets->int-be (conn-read c 2)))
                (127 (octets->int-be (conn-read c 8)))
                (t len)))
    (when (> len (* 64 1024 1024)) (ws-fail "frame too large (~D)" len))
    (let* ((mask (and masked (conn-read c 4)))
           (payload (if (zerop len) (make-octets 0) (conn-read c len))))
      (when mask (dotimes (i len) (setf (aref payload i) (logxor (aref payload i) (aref mask (logand i 3))))))
      (values opcode payload fin))))

(defun ws-message-available-p (ws)
  (and (ws-open ws) (ignore-errors (conn-ready-p (ws-conn ws)))))

(defun ws-receive (ws &key (timeout-ms 0))
  "Return the next text message, or NIL if none arrives within TIMEOUT-MS.
Control frames are handled transparently.  Signals WEBSOCKET-ERROR once the
peer closes."
  (let ((deadline (+ (monotonic-ms) timeout-ms)))
    (loop
      (unless (ws-open ws) (ws-fail "connection closed"))
      (if (ws-message-available-p ws)
          (multiple-value-bind (opcode payload fin) (%ws-read-frame ws)
            (case opcode
              (9 (%ws-send-frame ws 10 payload))     ; ping -> pong
              (10)                                   ; pong
              (8 (ignore-errors (%ws-send-frame ws 8 (subseq-octets payload 0 (min 2 (length payload)))))
                 (ws-close ws)
                 (ws-fail "closed by peer"))
              ((0 1 2)
               (when (/= opcode 0) (setf (ws-fragment-opcode ws) opcode (ws-fragments ws) '()))
               (push payload (ws-fragments ws))
               (when fin
                 (let ((data (apply #'concat-octets (reverse (ws-fragments ws))))
                       (op (ws-fragment-opcode ws)))
                   (setf (ws-fragments ws) '() (ws-fragment-opcode ws) nil)
                   (when (eql op 1) (return (utf8->string data))))))
              (t (ws-fail "unknown opcode ~D" opcode))))
          (if (>= (monotonic-ms) deadline)
              (return nil)
              (sleep-ms 5))))))

(defun ws-close (ws)
  (when (ws-open ws)
    (setf (ws-open ws) nil)
    (ignore-errors (%ws-send-frame ws 8 (octets 3 232)))
    (conn-close (ws-conn ws))))
