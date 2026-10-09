;;;; event.lisp — NIP-01 events
;;;;
;;;; Fields keep their wire representation: id, pubkey and sig are lowercase
;;;; hex strings, tags a list of lists of strings.  The id preimage is the
;;;; NIP-01 serialization [0,pubkey,created_at,kind,tags,content] produced by
;;;; TO-JSON, whose string escaping is NIP-01's.

(in-package #:cl-marmot)

(define-condition nostr-error (error)
  ((message :initarg :message :reader nostr-error-message))
  (:report (lambda (c s) (format s "Nostr: ~A" (nostr-error-message c)))))

(defun nostr-fail (fmt &rest args)
  (error 'nostr-error :message (apply #'format nil fmt args)))

(defstruct nostr-event
  id pubkey (created-at 0) (kind 1) (tags '()) (content "") sig)

(defun %tags->json (tags)
  (coerce (mapcar (lambda (tag) (coerce tag 'simple-vector)) tags) 'simple-vector))

(defun event-id-preimage (ev)
  (to-json (jarr 0 (nostr-event-pubkey ev) (nostr-event-created-at ev) (nostr-event-kind ev)
                 (%tags->json (nostr-event-tags ev)) (nostr-event-content ev))))

(defun compute-event-id (ev)
  (octets->hex (sha256 (string->utf8 (event-id-preimage ev)))))

(defun keypair-from-secret (sk)
  "Returns (values sk pubkey-octets)."
  (unless (secp256k1-valid-seckey-p sk) (nostr-fail "invalid secret key"))
  (values sk (secp256k1-xonly-pubkey sk)))

(defun generate-nostr-key ()
  (loop (let ((sk (random-octets 32)))
          (when (secp256k1-valid-seckey-p sk) (return sk)))))

(defun make-unsigned-event (&key pubkey (created-at (unix-time)) kind (tags '()) (content ""))
  "An event with its id computed and no signature (a NIP-59 rumor, or a Marmot
app event).  PUBKEY may be octets or hex."
  (let ((ev (make-nostr-event :pubkey (if (stringp pubkey) pubkey (octets->hex pubkey))
                              :created-at created-at :kind kind :tags tags :content content)))
    (setf (nostr-event-id ev) (compute-event-id ev))
    ev))

(defun sign-event (ev sk)
  "Fill in pubkey, id and sig from secret key SK (octets)."
  (setf (nostr-event-pubkey ev) (octets->hex (secp256k1-xonly-pubkey sk)))
  (setf (nostr-event-id ev) (compute-event-id ev))
  (setf (nostr-event-sig ev) (octets->hex (bip340-sign sk (hex->octets (nostr-event-id ev)))))
  ev)

(defun make-signed-event (sk &key (created-at (unix-time)) kind (tags '()) (content ""))
  (sign-event (make-nostr-event :created-at created-at :kind kind :tags tags :content content) sk))

(defun %lower-hex-p (s n)
  (and (stringp s) (= (length s) n)
       (every (lambda (c) (or (digit-char-p c) (find c "abcdef"))) s)))

(defun verify-event (ev)
  "True iff the id matches the content and the BIP-340 signature verifies."
  (and (%lower-hex-p (nostr-event-id ev) 64)
       (%lower-hex-p (nostr-event-pubkey ev) 64)
       (%lower-hex-p (nostr-event-sig ev) 128)
       (string= (nostr-event-id ev) (compute-event-id ev))
       (bip340-verify (hex->octets (nostr-event-pubkey ev))
                      (hex->octets (nostr-event-id ev))
                      (hex->octets (nostr-event-sig ev)))))

(defun event->jobj (ev)
  (let ((fields (list "id" (nostr-event-id ev)
                      "pubkey" (nostr-event-pubkey ev)
                      "created_at" (nostr-event-created-at ev)
                      "kind" (nostr-event-kind ev)
                      "tags" (%tags->json (nostr-event-tags ev))
                      "content" (nostr-event-content ev))))
    (apply #'jobj (if (nostr-event-sig ev) (append fields (list "sig" (nostr-event-sig ev))) fields))))

(defun event->json (ev) (to-json (event->jobj ev)))

(defun jobj->event (obj &key (allow-sig t) (require-sig nil) (strict nil))
  "Decode a JSON event object.  STRICT rejects unknown members (the Marmot app
payload rule); the caller decides whether a sig is allowed or required."
  (unless (jobj-p obj) (nostr-fail "event is not an object"))
  (when strict
    (dolist (cell (cdr obj))
      (unless (member (car cell) '("id" "pubkey" "created_at" "kind" "tags" "content" "sig")
                      :test #'string=)
        (nostr-fail "unknown event member ~S" (car cell)))))
  (let ((sig (jget obj "sig")))
    (when (and sig (not allow-sig)) (nostr-fail "event must not carry a sig"))
    (when (and require-sig (not (stringp sig))) (nostr-fail "event has no sig"))
    (let ((tags (jget obj "tags")))
      (unless (and (vectorp tags) (not (stringp tags))
                   (every (lambda (tag) (and (vectorp tag) (not (stringp tag)) (every #'stringp tag))) tags))
        (nostr-fail "malformed tags"))
      (let ((kind (jget obj "kind")) (created (jget obj "created_at")))
        (unless (and (integerp kind) (<= 0 kind 65535)) (nostr-fail "bad kind"))
        (unless (and (integerp created) (<= 0 created)) (nostr-fail "bad created_at"))
        (unless (stringp (jget obj "content")) (nostr-fail "bad content"))
        (unless (%lower-hex-p (jget obj "id") 64) (nostr-fail "bad id"))
        (unless (%lower-hex-p (jget obj "pubkey") 64) (nostr-fail "bad pubkey"))
        (make-nostr-event :id (jget obj "id") :pubkey (jget obj "pubkey") :created-at created
                          :kind kind :tags (map 'list (lambda (tag) (coerce tag 'list)) tags)
                          :content (jget obj "content") :sig (and (stringp sig) sig))))))

(defun json->event (string &rest args)
  (apply #'jobj->event (parse-json string) args))

;;; Tag helpers

(defun event-tags-named (ev name)
  (remove-if-not (lambda (tag) (and tag (string= (first tag) name))) (nostr-event-tags ev)))

(defun event-tag-value (ev name)
  "The single value of a singleton tag NAME; signals if the tag is missing,
repeated, or does not have exactly one value (Marmot's cardinality rule)."
  (let ((tags (event-tags-named ev name)))
    (unless (= (length tags) 1) (nostr-fail "expected exactly one ~S tag, got ~D" name (length tags)))
    (unless (= (length (first tags)) 2) (nostr-fail "~S tag must have exactly one value" name))
    (second (first tags))))

(defun event-tag-values (ev name)
  "All values of a single list tag NAME (the tag must appear exactly once)."
  (let ((tags (event-tags-named ev name)))
    (unless (= (length tags) 1) (nostr-fail "expected exactly one ~S tag, got ~D" name (length tags)))
    (rest (first tags))))

;;; Relay-list helpers (NIP-65 10002, NIP-17 10050)

(defun relay-list-event (sk kind relays &key write-only)
  (make-signed-event sk :kind kind
                        :tags (mapcar (lambda (r)
                                        (cond ((= kind 10050) (list "relay" r))
                                              (write-only (list "r" r "write"))
                                              (t (list "r" r))))
                                      relays)))

(defun nip65-write-relays (ev)
  (loop for tag in (event-tags-named ev "r")
        when (or (= (length tag) 2) (and (= (length tag) 3) (string= (third tag) "write")))
          collect (second tag)))

(defun nip17-inbox-relays (ev)
  (mapcar #'second (remove-if-not (lambda (tag) (= (length tag) 2)) (event-tags-named ev "relay"))))
