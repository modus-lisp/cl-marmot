;;;; wss.lisp — wss:// via seal, the pure-Common-Lisp TLS 1.3 client
;;;;
;;;; Loaded only by the CL-MARMOT/WSS system, which depends on seal (and so on
;;;; natrium).  seal speaks TLS over a pluggable TRANSPORT of three closures;
;;;; we give it one built on our own TCP stream so that, after the handshake,
;;;; READY-P can ask "is there anything to read?" without blocking — which the
;;;; single-threaded relay pool needs.  Certificate validation is seal's
;;;; default: chain to the system trust store, signatures, dates, hostname.

(in-package #:cl-marmot)

(defparameter *tls-verify* t
  "Passed to seal:connect as :verify.  T (full validation) unless you know why not.")

(defun seal-conn (host port)
  "A CONN carrying TLS to HOST:PORT."
  (multiple-value-bind (stream socket) (tcp-connect host port)
    (let* ((blocking t)
           (transport
             (seal::%make-transport
              :sender (lambda (bytes)
                        (write-sequence (coerce bytes '(simple-array (unsigned-byte 8) (*))) stream)
                        (force-output stream)
                        t)
              :receiver (lambda ()
                          ;; blocking: wait for at least one byte; either way,
                          ;; then drain what is already buffered
                          (when (or blocking (ignore-errors (listen stream)))
                            (let ((first (read-byte stream nil nil)))
                              (when first
                                (let ((out (make-array 1 :element-type '(unsigned-byte 8)
                                                         :adjustable t :fill-pointer 1
                                                         :initial-element first)))
                                  (loop while (and (< (fill-pointer out) 16384)
                                                   (ignore-errors (listen stream)))
                                        do (let ((b (read-byte stream nil nil)))
                                             (if b (vector-push-extend b out) (return))))
                                  (coerce-octets out))))))
              :closer (lambda () (ignore-errors (close stream)) (tcp-close socket))))
           (tls (handler-case (seal:connect host port :transport transport :verify *tls-verify*
                                                      :alpn nil)
                  (error (c) (ignore-errors (close stream)) (tcp-close socket)
                    (ws-fail "TLS to ~A:~D: ~A" host port c))))
           (pending (make-octets 0)))
      (labels ((pull (block)
                 (setf blocking block)
                 (let ((chunk (seal:tls-recv tls)))
                   (setf blocking t)
                   (when chunk
                     (setf pending (concat-octets pending (coerce-octets chunk))))
                   chunk)))
        (make-conn
         :read-fn (lambda (n)
                    (loop while (< (length pending) n)
                          do (unless (pull t) (ws-fail "TLS connection closed")))
                    (prog1 (subseq-octets pending 0 n)
                      (setf pending (subseq-octets pending n))))
         :write-fn (lambda (octets) (seal:tls-send tls octets))
         :ready-fn (lambda ()
                     (or (plusp (length pending))
                         (and (ignore-errors (listen stream))
                              (progn (pull nil) (plusp (length pending))))))
         :close-fn (lambda () (ignore-errors (seal:tls-close tls))))))))

(setf *tls-connect-function* #'seal-conn)
