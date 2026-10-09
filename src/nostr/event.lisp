;;;; event.lisp — Nostr events, gift wraps and relays, through cl-nostr
;;;;
;;;; Events are cl-nostr's EVENT struct (accessors EV:EVENT-ID, EV:EVENT-PUBKEY,
;;;; … with hex strings for id/pubkey/sig and tags as lists of lists of strings);
;;;; ids, signatures, NIP-44 and NIP-59 are cl-nostr's.  What stays here is the
;;;; Marmot-side strictness cl-nostr does not need for chat: decoding an event
;;;; from JSON with unknown members, duplicate keys, a sig where none may appear,
;;;; or a mistyped field all rejected (application-messages.md "Encoding"), the
;;;; exact-cardinality tag readers of transports/nostr.md, and an encoder for
;;;; unsigned events (rumors, app payloads) that writes no sig member at all.

(in-package #:cl-marmot)

(define-condition nostr-error (error)
  ((message :initarg :message :reader nostr-error-message))
  (:report (lambda (c s) (format s "Nostr: ~A" (nostr-error-message c)))))

(defun nostr-fail (fmt &rest args)
  (error 'nostr-error :message (apply #'format nil fmt args)))

;;; Keys

(defun generate-nostr-key ()
  (coerce-octets (k:keypair-secret-key (k:generate-keypair))))

(defun %keypair (sk) (k:keypair-from-secret (ensure-octets sk)))

;;; Construction

(defun compute-event-id (e)
  (ev:compute-id (ev:event-pubkey e) (ev:event-created-at e) (ev:event-kind e)
                 (ev:event-tags e) (ev:event-content e)))

(defun make-unsigned-event (&key pubkey (created-at (unix-time)) kind (tags '()) (content ""))
  "An event with its id and no signature (a NIP-59 rumor or a Marmot app
event).  PUBKEY may be octets or hex."
  (let ((e (ev:make-event :pubkey (if (stringp pubkey) pubkey (octets->hex pubkey))
                          :created-at created-at :kind kind :tags tags :content content)))
    (setf (ev:event-id e) (compute-event-id e))
    e))

(defun make-signed-event (sk &key (created-at (unix-time)) kind (tags '()) (content ""))
  (ev:build-event (%keypair sk) kind content :tags tags :created-at created-at))

(defun verify-event (e) (and (ignore-errors (ev:verify-event e)) t))

;;; JSON

(defun %tags->json (tags)
  (coerce (mapcar (lambda (tag) (coerce tag 'simple-vector)) tags) 'simple-vector))

(defun event->jobj (e)
  (let ((fields (list "id" (ev:event-id e) "pubkey" (ev:event-pubkey e)
                      "created_at" (ev:event-created-at e) "kind" (ev:event-kind e)
                      "tags" (%tags->json (ev:event-tags e)) "content" (ev:event-content e))))
    (apply #'jobj (if (ev:event-sig e) (append fields (list "sig" (ev:event-sig e))) fields))))

(defun event->json (e) (to-json (event->jobj e)))

(defun %lower-hex-p (s n)
  (and (stringp s) (= (length s) n)
       (every (lambda (c) (or (digit-char-p c) (find c "abcdef"))) s)))

(defun jobj->event (obj &key (allow-sig t) (require-sig nil) (strict nil))
  "Decode a JSON event object (as parsed by PARSE-JSON).  STRICT rejects unknown
members; the caller decides whether a sig is allowed or required."
  (unless (jobj-p obj) (nostr-fail "event is not an object"))
  (when strict
    (dolist (cell (cdr obj))
      (unless (member (car cell) '("id" "pubkey" "created_at" "kind" "tags" "content" "sig")
                      :test #'string=)
        (nostr-fail "unknown event member ~S" (car cell)))))
  (let ((sig (jget obj "sig")) (tags (jget obj "tags"))
        (kind (jget obj "kind")) (created (jget obj "created_at")))
    (when (and sig (not allow-sig)) (nostr-fail "event must not carry a sig"))
    (when (and require-sig (not (stringp sig))) (nostr-fail "event has no sig"))
    (unless (and (vectorp tags) (not (stringp tags))
                 (every (lambda (tag) (and (vectorp tag) (not (stringp tag)) (every #'stringp tag))) tags))
      (nostr-fail "malformed tags"))
    (unless (and (integerp kind) (<= 0 kind 65535)) (nostr-fail "bad kind"))
    (unless (and (integerp created) (<= 0 created)) (nostr-fail "bad created_at"))
    (unless (stringp (jget obj "content")) (nostr-fail "bad content"))
    (unless (%lower-hex-p (jget obj "id") 64) (nostr-fail "bad id"))
    (unless (%lower-hex-p (jget obj "pubkey") 64) (nostr-fail "bad pubkey"))
    (ev:make-event :id (jget obj "id") :pubkey (jget obj "pubkey") :created-at created :kind kind
                   :tags (map 'list (lambda (tag) (coerce tag 'list)) tags)
                   :content (jget obj "content") :sig (and (stringp sig) sig))))

(defun json->event (string &rest args)
  (apply #'jobj->event (parse-json string) args))

;;; Tags (transports/nostr.md "Event identity and tag cardinality")

(defun event-tags-named (e name)
  (remove-if-not (lambda (tag) (and tag (string= (first tag) name))) (ev:event-tags e)))

(defun event-tag-value (e name)
  "The single value of a singleton tag NAME; signals if it is missing, repeated,
or does not have exactly one value."
  (let ((tags (event-tags-named e name)))
    (unless (= (length tags) 1) (nostr-fail "expected exactly one ~S tag, got ~D" name (length tags)))
    (unless (= (length (first tags)) 2) (nostr-fail "~S tag must have exactly one value" name))
    (second (first tags))))

(defun event-tag-values (e name)
  "All values of the single list tag NAME (which must appear exactly once)."
  (let ((tags (event-tags-named e name)))
    (unless (= (length tags) 1) (nostr-fail "expected exactly one ~S tag, got ~D" name (length tags)))
    (rest (first tags))))

;;; Relay lists (NIP-65 kind 10002, NIP-17 kind 10050)

(defun relay-list-event (sk kind relays)
  (make-signed-event sk :kind kind
                        :tags (mapcar (lambda (r) (if (= kind 10050) (list "relay" r) (list "r" r)))
                                      relays)))

(defun nip65-write-relays (e)
  (loop for tag in (event-tags-named e "r")
        when (or (= (length tag) 2) (and (= (length tag) 3) (string= (third tag) "write")))
          collect (second tag)))

(defun nip17-inbox-relays (e)
  (mapcar #'second (remove-if-not (lambda (tag) (= (length tag) 2)) (event-tags-named e "relay"))))

;;; NIP-59

(defun gift-wrap (rumor author-sk recipient-pubkey-hex)
  "Wrap the unsigned RUMOR (authored by AUTHOR-SK's key) for RECIPIENT."
  (nip59:wrap-rumor (%keypair author-sk) recipient-pubkey-hex (ev:event-kind rumor) (ev:event-content rumor)
                    :tags (ev:event-tags rumor) :created-at (ev:event-created-at rumor)))

(defun gift-unwrap (wrap my-sk)
  "Returns (values rumor seal); signals NOSTR-ERROR on any failure."
  (handler-case (nip59:unwrap-rumor (%keypair my-sk) wrap)
    (error (c) (nostr-fail "~A" c))))

;;; NIP-19

(defun npub-encode (pubkey) (b32:npub-encode (ensure-octets pubkey)))
(defun nsec-decode (nsec) (coerce-octets (b32:nsec-decode nsec)))

(defun parse-pubkey (string)
  "An npub, nprofile, 64-hex pubkey or NIP-05 address (name@domain), as 32 octets."
  (let ((hex (handler-case (if (find #\@ string)
                               (nip05:resolve-pubkey string)
                               (b32:pubkey-hex string))
               (error () nil))))
    (unless (%lower-hex-p hex 64) (nostr-fail "not a public key: ~A" string))
    (hex->octets hex)))
