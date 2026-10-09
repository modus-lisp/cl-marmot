;;;; media.lisp — encrypted media v2 (features/encrypted-media.md)
;;;;
;;;; An attachment is a file encrypted under a key derived from the group's
;;;; media exporter secret at the epoch of the message that carries it, stored
;;;; as an opaque blob (Blossom), and described by one NIP-92 `imeta' tag on a
;;;; kind 9 chat message.  This file is the protocol half, with no network:
;;;;
;;;;   - the 0x800b group policy codec (allowed locator kinds, default endpoints)
;;;;   - media-type canonicalization (foundation/canonical-encoding.md)
;;;;   - building and strictly parsing `imeta' tags
;;;;   - file key derivation, encryption and decryption
;;;;   - the per-chat table of media secrets, so media from an epoch the chat
;;;;     has moved past can still be opened
;;;;
;;;; Uploading and fetching live in client/media.lisp.

(in-package #:cl-marmot)

(defparameter +media-format+ "encrypted-media-v2")
(defparameter +blossom-locator+ "blossom-v1")

(defparameter *default-media-endpoints* '("https://blossom.primal.net/")
  "Blossom servers written into the media policy of chats we create, in
upload/fetch priority order.")

(defparameter *max-media-secrets* 512
  "How many (epoch, branch) media secrets a chat keeps.  A secret is recorded
only when a message carrying media is sent or delivered in that epoch.")

;;; ---------------------------------------------------------------------------
;;; URLs — just enough of WHATWG for the checks the spec asks for

(defun %parse-http-url (string)
  "Split an http(s) URL into (values scheme host port path-and-rest) or NIL.
Rejects userinfo, missing hosts, whitespace and control characters."
  (when (and (stringp string) (plusp (length string))
             (notany (lambda (c) (or (<= (char-code c) 32) (= (char-code c) 127) (char= c #\\))) string))
    (let* ((sep (search "://" string))
           (scheme (and sep (string-downcase (subseq string 0 sep)))))
      (when (member scheme '("http" "https") :test #'string=)
        (let* ((start (+ sep 3))
               (end (or (position-if (lambda (c) (find c "/?#")) string :start start) (length string)))
               (authority (subseq string start end))
               (colon (position #\: authority :from-end t))
               (host (if (and colon (not (find #\] authority :start colon))) (subseq authority 0 colon) authority))
               (port (and colon (not (find #\] authority :start colon)) (subseq authority (1+ colon)))))
          (when (and (plusp (length host)) (not (find #\@ authority))
                     (or (null port) (and (plusp (length port)) (every #'digit-char-p port))))
            (values scheme host (and port (parse-integer port)) (subseq string end) port)))))))

(defun %normalized-endpoint-url-p (string)
  "Is STRING an http(s) URL with no userinfo, query or fragment, already in the
form a WHATWG parser would serialize it to (lowercase scheme and host, no
default port, a path)?  An approximation that accepts what real policies hold."
  (multiple-value-bind (scheme host port rest port-text) (%parse-http-url string)
    (and scheme
         (<= 1 (length (string->utf8 string)) 2048)
         (string= (subseq string 0 (length scheme)) scheme)
         (string= host (string-downcase host))
         (or (null port)
             (and (string= port-text (format nil "~D" port))
                  (/= port (if (string= scheme "http") 80 443))))
         (plusp (length rest)) (char= (char rest 0) #\/)
         (not (find #\? rest)) (not (find #\# rest))
         (not (search "/./" rest)) (not (search "/../" rest)))))

(defun %loopback-host-p (host)
  (let ((h (string-downcase (string-trim "[]" host))))
    (or (string= h "localhost") (string= h "::1") (string= h "0.0.0.0")
        (and (> (length h) 4) (string= (subseq h 0 4) "127.")))))

;;; ---------------------------------------------------------------------------
;;; 0x800b marmot.group.encrypted-media.v2

(defun %locator-kind-p (k)
  (and (stringp k) (<= 1 (length k) 64)
       (every (lambda (c) (or (char<= #\a c #\z) (digit-char-p c) (char= c #\-))) k)))

(defun encode-media-policy (allowed-kinds endpoints)
  "ENDPOINTS: list of (locator-kind . base-url).  Order is kept: it is the
fallback priority, and part of the canonical value."
  (with-writer (w)
    (w-opaque w (string->utf8 +media-format+) :quic t)
    (w-vector w allowed-kinds (lambda (w2 k) (w-opaque w2 (string->utf8 k) :quic t)) :quic t)
    (w-vector w endpoints (lambda (w2 e)
                            (w-opaque w2 (string->utf8 (car e)) :quic t)
                            (w-opaque w2 (string->utf8 (cdr e)) :quic t))
              :quic t)))

(defun decode-media-policy (octets)
  "Returns (values allowed-kinds endpoints), validated; signals MARMOT-ERROR."
  (destructuring-bind (fmt kinds endpoints)
      (%decode-marmot octets
                      (lambda (r)
                        (list (r-opaque r :quic t)
                              (r-vector r (lambda (r2) (utf8->string (r-opaque r2 :quic t))) :quic t)
                              (r-vector r (lambda (r2) (cons (utf8->string (r-opaque r2 :quic t))
                                                             (utf8->string (r-opaque r2 :quic t))))
                                        :quic t)))
                      "media policy")
    (unless (string= (utf8->string fmt) +media-format+) (marmot-fail "media policy: unknown media format"))
    (unless (octets= octets (encode-media-policy kinds endpoints))
      (marmot-fail "media policy: not canonically encoded"))
    (unless (<= 1 (length kinds) 16) (marmot-fail "media policy: 1..16 locator kinds"))
    (unless (<= 1 (length endpoints) 16) (marmot-fail "media policy: 1..16 endpoints"))
    (unless (every #'%locator-kind-p kinds) (marmot-fail "media policy: bad locator kind"))
    (unless (= (length kinds) (length (remove-duplicates kinds :test #'string=)))
      (marmot-fail "media policy: duplicate locator kind"))
    (unless (= (length endpoints) (length (remove-duplicates endpoints :test #'equal)))
      (marmot-fail "media policy: duplicate endpoint"))
    (dolist (e endpoints)
      (unless (member (car e) kinds :test #'string=) (marmot-fail "media policy: endpoint kind not allowed"))
      (unless (%normalized-endpoint-url-p (cdr e)) (marmot-fail "media policy: endpoint URL not normalized")))
    (values kinds endpoints)))

(defun group-media-policy (mls)
  "Returns (values allowed-kinds endpoints) when the group requires a valid
0x800b policy, else NIL."
  (let ((d (app-data-get (%gc-dict mls) +c-encrypted-media-v2+)))
    (when (and d (member +c-encrypted-media-v2+ (group-required-components mls)))
      (handler-case (decode-media-policy d)
        (marmot-error () nil)))))

;;; ---------------------------------------------------------------------------
;;; Media type canonicalization

(defun canonical-media-type (string)
  "The canonical form of a MIME type, or NIL if it is not one."
  (let* ((s (subseq string 0 (or (position #\; string) (length string))))
         (ws (coerce '(#\Tab #\Newline #\Page #\Return #\Space) 'string))
         (s (string-trim ws s)))
    (when (every (lambda (c) (< (char-code c) 128)) s)
      (let* ((s (string-downcase s))
             (slash (position #\/ s)))
        (flet ((token-p (x) (and (<= 1 (length x) 64)
                                 (every (lambda (c) (or (alphanumericp c) (find c "!#$%&'*+-.^_`|~"))) x))))
          (when (and slash (= (count #\/ s) 1) (<= (length s) 128)
                     (token-p (subseq s 0 slash)) (token-p (subseq s (1+ slash))))
            (if (string= s "image/jpg") "image/jpeg" s)))))))

(defparameter *media-types-by-extension*
  '(("jpg" . "image/jpeg") ("jpeg" . "image/jpeg") ("png" . "image/png") ("gif" . "image/gif")
    ("webp" . "image/webp") ("heic" . "image/heic") ("avif" . "image/avif") ("svg" . "image/svg+xml")
    ("mp4" . "video/mp4") ("mov" . "video/quicktime") ("webm" . "video/webm")
    ("mp3" . "audio/mpeg") ("m4a" . "audio/mp4") ("ogg" . "audio/ogg") ("opus" . "audio/opus") ("wav" . "audio/wav")
    ("pdf" . "application/pdf") ("txt" . "text/plain") ("md" . "text/markdown") ("json" . "application/json")
    ("zip" . "application/zip")))

(defun guess-media-type (filename)
  (let ((dot (position #\. filename :from-end t)))
    (or (and dot (cdr (assoc (string-downcase (subseq filename (1+ dot))) *media-types-by-extension*
                             :test #'string=)))
        "application/octet-stream")))

(defun %filename-ok-p (name)
  (and (stringp name) (not (find (code-char 0) name)) (<= 1 (length (string->utf8 name)) 255)))

;;; ---------------------------------------------------------------------------
;;; Keys and encryption

(defun media-secret (mls)
  "MLS-Exporter(\"marmot\", \"encrypted-media\", 32) of MLS's epoch."
  (mls-group-export mls "marmot" "encrypted-media" 32))

(defun %media-context (pt-sha media-type filename)
  (concat-octets (string->utf8 +media-format+) (octets 0) pt-sha (octets 0)
                 (string->utf8 media-type) (octets 0) (string->utf8 filename)))

(defun media-file-key (secret pt-sha media-type filename)
  (hkdf-expand secret (concat-octets (%media-context pt-sha media-type filename) (octets 0) (string->utf8 "key")) 32))

(defun encrypt-media (secret plaintext media-type filename &key (nonce (random-octets 12)))
  "Encrypt PLAINTEXT.  Returns an attachment plist (the imeta fields, without
locators) and the ciphertext."
  (let* ((media-type (or (canonical-media-type media-type) (marmot-fail "not a media type: ~A" media-type)))
         (plaintext (ensure-octets plaintext))
         (pt-sha (sha256 plaintext)))
    (unless (%filename-ok-p filename) (marmot-fail "file name must be 1..255 UTF-8 bytes with no NUL"))
    (let ((ct (chacha20-poly1305-encrypt (media-file-key secret pt-sha media-type filename)
                                         nonce plaintext (%media-context pt-sha media-type filename))))
      (values (list :ciphertext-sha256 (octets->hex (sha256 ct)) :plaintext-sha256 (octets->hex pt-sha)
                    :nonce (octets->hex nonce) :media-type media-type :filename filename
                    :size (length plaintext))
              ct))))

(defun decrypt-media (secret attachment ciphertext)
  "Decrypt and check an attachment's CIPHERTEXT; signals MARMOT-ERROR if it does
not hash, decrypt or verify."
  (let ((pt-sha (hex->octets (string-downcase (getf attachment :plaintext-sha256))))
        (mt (getf attachment :media-type)) (fn (getf attachment :filename)))
    (unless (octets= (sha256 ciphertext) (hex->octets (string-downcase (getf attachment :ciphertext-sha256))))
      (marmot-fail "media blob does not match its ciphertext hash"))
    (let ((pt (handler-case (chacha20-poly1305-decrypt (media-file-key secret pt-sha mt fn)
                                                       (hex->octets (string-downcase (getf attachment :nonce)))
                                                       ciphertext (%media-context pt-sha mt fn))
                (error () (marmot-fail "media does not decrypt")))))
      (unless (octets= (sha256 pt) pt-sha) (marmot-fail "decrypted media does not match its plaintext hash"))
      pt)))

;;; ---------------------------------------------------------------------------
;;; imeta tags

(defun imeta-tag (attachment)
  "The NIP-92 tag for ATTACHMENT (a plist with :locators, a list of (kind . url))."
  (append (list "imeta" (format nil "v ~A" +media-format+))
          (mapcar (lambda (l) (format nil "locator ~A ~A" (car l) (cdr l))) (getf attachment :locators))
          (list (format nil "ciphertext_sha256 ~A" (getf attachment :ciphertext-sha256))
                (format nil "plaintext_sha256 ~A" (getf attachment :plaintext-sha256))
                (format nil "nonce ~A" (getf attachment :nonce))
                (format nil "m ~A" (getf attachment :media-type))
                (format nil "filename ~A" (getf attachment :filename)))
          (and (getf attachment :dim) (list (format nil "dim ~A" (getf attachment :dim))))
          (and (getf attachment :thumbhash) (list (format nil "thumbhash ~A" (getf attachment :thumbhash))))))

(defun %hex-of-length-p (s n)
  (and (stringp s) (= (length s) n) (every (lambda (c) (digit-char-p c 16)) s)))

(defun parse-imeta (tag)
  "A validated attachment plist, or (values NIL reason).  Rejection is
attachment-local: the caller keeps the message and its other attachments."
  (let ((fields '()) (locators '()) (singles '("v" "ciphertext_sha256" "plaintext_sha256" "nonce" "m" "filename"
                                               "dim" "thumbhash")))
    (flet ((no (why) (return-from parse-imeta (values nil why))))
      (unless (equal (first tag) "imeta") (no "not an imeta tag"))
      (dolist (f (rest tag))
        (let* ((sp (position #\Space f))
               (key (if sp (subseq f 0 sp) f))
               (value (and sp (subseq f (1+ sp)))))
          (cond ((string= key "blurhash") (no "blurhash is not allowed"))
                ((string= key "locator")
                 (let ((sp2 (and value (position #\Space value))))
                   (unless (and sp2 (plusp sp2) (< (1+ sp2) (length value))) (no "locator needs a kind and a value"))
                   (push (cons (subseq value 0 sp2) (subseq value (1+ sp2))) locators)))
                ((member key singles :test #'string=)
                 (unless value (no (format nil "~A has no value" key)))
                 (when (assoc key fields :test #'string=) (no (format nil "duplicate ~A" key)))
                 (push (cons key value) fields)))))
      (flet ((field (k) (cdr (assoc k fields :test #'string=))))
        (unless (equal (field "v") +media-format+) (no "not encrypted-media-v2"))
        (dolist (k '("ciphertext_sha256" "plaintext_sha256" "nonce" "m" "filename"))
          (when (or (null (field k)) (zerop (length (field k)))) (no (format nil "missing ~A" k))))
        (unless locators (no "no locator"))
        (dolist (l locators)
          (when (and (string= (car l) +blossom-locator+) (null (%parse-http-url (cdr l))))
            (no "blossom locator is not an http(s) URL")))
        (unless (%hex-of-length-p (field "ciphertext_sha256") 64) (no "bad ciphertext_sha256"))
        (unless (%hex-of-length-p (field "plaintext_sha256") 64) (no "bad plaintext_sha256"))
        (unless (%hex-of-length-p (field "nonce") 24) (no "nonce is not 12 bytes"))
        (unless (equal (canonical-media-type (field "m")) (field "m")) (no "media type is not canonical"))
        (unless (%filename-ok-p (field "filename")) (no "bad file name"))
        (list :locators (reverse locators)
              :ciphertext-sha256 (field "ciphertext_sha256") :plaintext-sha256 (field "plaintext_sha256")
              :nonce (field "nonce") :media-type (field "m") :filename (field "filename")
              :dim (field "dim") :thumbhash (field "thumbhash"))))))

(defun message-imeta-tags (tags) (remove-if-not (lambda (tg) (equal (first tg) "imeta")) tags))

;;; ---------------------------------------------------------------------------
;;; Media secrets by (epoch, branch)

(defun %media-secret-key (epoch node-digest) (format nil "~D:~A" epoch (or node-digest "")))

(defun remember-media-secret (mg state node-digest)
  "Keep STATE's media secret so media sent in its epoch opens after the chat moves on."
  (let ((key (%media-secret-key (mls-group-epoch state) node-digest))
        (table (marmot-group-media-secrets mg)))
    (unless (assoc key table :test #'string=)
      (setf (marmot-group-media-secrets mg)
            (let ((new (cons (cons key (media-secret state)) table)))
              (if (> (length new) *max-media-secrets*) (subseq new 0 *max-media-secrets*) new))))))

(defun message-media-secret (mg message)
  "The media secret for MESSAGE (a delivered or sent message plist), or NIL."
  (cdr (assoc (%media-secret-key (getf message :epoch) (getf message :node))
              (marmot-group-media-secrets mg) :test #'string=)))
