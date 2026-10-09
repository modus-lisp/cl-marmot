;;;; relay.lisp — NIP-01 relay client and a small relay pool
;;;;
;;;; Everything is driven by RELAY-POLL / POOL-POLL: there are no threads.
;;;; Incoming EVENTs for a live subscription go to that subscription's handler;
;;;; OK / EOSE / CLOSED / NOTICE update relay state that the blocking helpers
;;;; (RELAY-PUBLISH, RELAY-QUERY) wait on by polling.

(in-package #:cl-marmot)

(defvar *relay-log* nil "When non-NIL, a stream for relay protocol traces.")

(defstruct relay
  url ws
  (subscriptions (make-hash-table :test #'equal))   ; sub-id -> handler (lambda (event))
  (eose (make-hash-table :test #'equal))            ; sub-id -> T
  (closed (make-hash-table :test #'equal))          ; sub-id -> message
  (oks (make-hash-table :test #'equal))             ; event-id -> (accepted . message)
  (notices '())
  (error nil))

(defvar *sub-counter* 0)
(defun %new-sub-id () (format nil "cm~36R~36R" (incf *sub-counter*) (octets->int-be (random-octets 4))))

(defun relay-connect (url)
  (make-relay :url url :ws (ws-connect url)))

(defun relay-connected-p (relay)
  (and (relay-ws relay) (ws-open (relay-ws relay))))

(defun relay-close (relay)
  (when (relay-ws relay) (ws-close (relay-ws relay))))

(defun %relay-send (relay &rest items)
  (let ((text (to-json (coerce items 'simple-vector))))
    (when *relay-log* (format *relay-log* "~&>> ~A ~A~%" (relay-url relay) (subseq text 0 (min 300 (length text)))))
    (ws-send-text (relay-ws relay) text)))

(defun %relay-dispatch (relay text)
  (when *relay-log* (format *relay-log* "~&<< ~A ~A~%" (relay-url relay) (subseq text 0 (min 300 (length text)))))
  (let ((msg (handler-case (parse-json text) (json-error () nil))))
    (when (and (vectorp msg) (plusp (length msg)) (stringp (aref msg 0)))
      (let ((type (aref msg 0)))
        (cond ((and (string= type "EVENT") (= (length msg) 3))
               (let ((handler (gethash (aref msg 1) (relay-subscriptions relay))))
                 (when handler
                   (let ((ev (handler-case (jobj->event (aref msg 2) :require-sig t)
                               (nostr-error () nil))))
                     ;; never trust an event before its id and signature verify
                     (when (and ev (verify-event ev))
                       (funcall handler ev relay))))))
              ((and (string= type "OK") (>= (length msg) 3))
               (setf (gethash (aref msg 1) (relay-oks relay))
                     (cons (eq (aref msg 2) :true) (if (> (length msg) 3) (aref msg 3) ""))))
              ((and (string= type "EOSE") (= (length msg) 2))
               (setf (gethash (aref msg 1) (relay-eose relay)) t))
              ((and (string= type "CLOSED") (>= (length msg) 2))
               (setf (gethash (aref msg 1) (relay-closed relay)) (if (> (length msg) 2) (aref msg 2) "")))
              ((string= type "NOTICE")
               (push (if (> (length msg) 1) (aref msg 1) "") (relay-notices relay))))))))

(defun relay-poll (relay &key (timeout-ms 0))
  "Process every message that arrives within TIMEOUT-MS.  Returns the count."
  (let ((n 0) (deadline (+ (monotonic-ms) timeout-ms)))
    (handler-case
        (loop
          (let ((text (ws-receive (relay-ws relay) :timeout-ms (max 0 (- deadline (monotonic-ms))))))
            (if text
                (progn (incf n) (%relay-dispatch relay text))
                (return))))
      (websocket-error (c) (setf (relay-error relay) c)))
    n))

(defun %wait-until (relay pred timeout-ms)
  (let ((deadline (+ (monotonic-ms) timeout-ms)))
    (loop
      (when (funcall pred) (return t))
      (when (or (>= (monotonic-ms) deadline) (not (relay-connected-p relay))) (return nil))
      (relay-poll relay :timeout-ms (min 50 (max 1 (- deadline (monotonic-ms))))))))

(defun relay-publish (relay event &key (timeout-ms 10000))
  "Send EVENT and wait for the relay's OK.  Returns (values accepted message)."
  (let ((id (nostr-event-id event)))
    (remhash id (relay-oks relay))
    (%relay-send relay "EVENT" (event->jobj event))
    (if (%wait-until relay (lambda () (gethash id (relay-oks relay))) timeout-ms)
        (let ((ok (gethash id (relay-oks relay))))
          (values (car ok) (cdr ok)))
        (values nil "timeout"))))

(defun relay-subscribe (relay filters handler &key (sub-id (%new-sub-id)))
  "Open a subscription.  HANDLER is called with (event relay) for each verified
event.  FILTERS is a list of filter JOBJs.  Returns the subscription id."
  (setf (gethash sub-id (relay-subscriptions relay)) handler)
  (remhash sub-id (relay-eose relay))
  (apply #'%relay-send relay "REQ" sub-id filters)
  sub-id)

(defun relay-unsubscribe (relay sub-id)
  (remhash sub-id (relay-subscriptions relay))
  (when (relay-connected-p relay)
    (ignore-errors (%relay-send relay "CLOSE" sub-id))))

(defun relay-query (relay filters &key (timeout-ms 10000))
  "Fetch stored events matching FILTERS (until EOSE).  Returns a list of
verified events, de-duplicated by id."
  (let* ((events '())
         (sub (relay-subscribe relay filters
                               (lambda (ev r) (declare (ignore r))
                                 (unless (find (nostr-event-id ev) events :key #'nostr-event-id :test #'string=)
                                   (push ev events))))))
    (%wait-until relay (lambda () (or (gethash sub (relay-eose relay)) (gethash sub (relay-closed relay))))
                 timeout-ms)
    (relay-unsubscribe relay sub)
    (nreverse events)))

;;; ---------------------------------------------------------------------------
;;; Pool

(defstruct pool
  (relays (make-hash-table :test #'equal)))   ; url -> relay (or NIL after a failure)

(defun pool-relay (pool url)
  "The connected relay for URL, connecting on demand.  NIL if unreachable."
  (let ((r (gethash url (pool-relays pool))))
    (if (and r (relay-connected-p r))
        r
        (let ((new (handler-case (relay-connect url)
                     (error (c)
                       (when *relay-log* (format *relay-log* "~&!! ~A: ~A~%" url c))
                       nil))))
          (setf (gethash url (pool-relays pool)) new)
          new))))

(defun pool-publish (pool urls event &key (timeout-ms 10000))
  "Publish EVENT to every URL.  Returns a list of (url accepted message); the
publish obligation is met when at least one entry is accepted."
  (loop for url in (remove-duplicates urls :test #'string=)
        collect (let ((r (pool-relay pool url)))
                  (if r
                      (multiple-value-bind (ok msg) (relay-publish r event :timeout-ms timeout-ms)
                        (list url ok msg))
                      (list url nil "unreachable")))))

(defun publish-accepted-p (results) (some #'second results))

(defun pool-query (pool urls filters &key (timeout-ms 10000))
  "Union of RELAY-QUERY over URLS, de-duplicated by event id."
  (let ((seen (make-hash-table :test #'equal)) (out '()))
    (dolist (url (remove-duplicates urls :test #'string=))
      (let ((r (pool-relay pool url)))
        (when r
          (dolist (ev (relay-query r filters :timeout-ms timeout-ms))
            (unless (gethash (nostr-event-id ev) seen)
              (setf (gethash (nostr-event-id ev) seen) t)
              (push ev out))))))
    (nreverse out)))

(defun pool-poll (pool &key (timeout-ms 0))
  (let ((deadline (+ (monotonic-ms) timeout-ms)))
    (loop
      (loop for r being the hash-values of (pool-relays pool)
            when (and r (relay-connected-p r)) do (relay-poll r))
      (when (>= (monotonic-ms) deadline) (return))
      (sleep-ms 10))))

(defun pool-close (pool)
  (loop for r being the hash-values of (pool-relays pool)
        when r do (relay-close r))
  (clrhash (pool-relays pool)))

(defun filter (&rest kvs)
  "Build a NIP-01 filter: (filter \"kinds\" '(1059) \"#p\" (list hex) \"limit\" 10).
List values become JSON arrays."
  (apply #'jobj (loop for (k v) on kvs by #'cddr
                      append (list k (if (listp v) (coerce v 'simple-vector) v)))))
