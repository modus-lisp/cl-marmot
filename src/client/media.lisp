;;;; media.lisp — sending and fetching encrypted attachments over Blossom
;;;;
;;;; Sending: encrypt each file under the chat's current media secret, upload
;;;; the ciphertext to the first of the chat's policy endpoints that takes it
;;;; (BUD-02 PUT /upload, authorized by a kind 24242 event signed with the
;;;; account key, as mdk does), then send one kind 9 message whose content is
;;;; the caption and which carries one `imeta' tag per file.
;;;;
;;;; Fetching: try the reference's own locators, then the policy endpoints'
;;;; fallback URLs (server_root/ciphertext_sha256); a blob is only accepted if
;;;; it hashes to ciphertext_sha256, decrypts, and the plaintext hashes to
;;;; plaintext_sha256.
;;;;
;;;; Loopback endpoints (localhost, 127.x, ::1) are never contacted unless
;;;; *ALLOW-LOOPBACK-MEDIA* is true: a group policy is chosen by an admin, and
;;;; pointing members' clients at their own machine's services is an attack.

(in-package #:cl-marmot)

(defparameter *allow-loopback-media* (equal (getenv "MARMOT_ALLOW_LOOPBACK_MEDIA") "1")
  "Contact Blossom servers on loopback addresses (development and tests).")

(defun %contactable-url-p (url)
  (multiple-value-bind (scheme host) (%parse-http-url url)
    (and scheme (or *allow-loopback-media* (not (%loopback-host-p host))))))

(defun %media-endpoints (mg &optional server)
  "Upload/fetch servers for MG: SERVER if given, else the policy's Blossom endpoints."
  (if server
      (list server)
      (multiple-value-bind (kinds endpoints) (group-media-policy (marmot-group-mls mg))
        (declare (ignore kinds))
        (loop for (kind . url) in endpoints
              when (string= kind +blossom-locator+) collect url))))

(defun %upload-blob (acct servers ciphertext)
  "Upload CIPHERTEXT to the first server in SERVERS that takes it.  Returns the
locator URL (the server's descriptor url, else server_root/hash)."
  (let ((failures '()))
    (dolist (server servers)
      (if (not (%contactable-url-p server))
          (push (format nil "~A: not contacted (loopback)" server) failures)
          (handler-case
              (multiple-value-bind (hash descriptor url)
                  (blossom:blossom-upload server ciphertext (%keypair (account-sk acct)))
                (declare (ignore hash))
                (let ((given (and (hash-table-p descriptor) (gethash "url" descriptor))))
                  (return-from %upload-blob
                    (if (and (stringp given) (%parse-http-url given)) given url))))
            (error (c) (push (format nil "~A: ~A" server c) failures)))))
    (marmot-fail "no Blossom server took the upload~{~%  ~A~}" (reverse failures))))

(defun send-media (acct mg files &key (caption "") server)
  "Send FILES, a list of plists (:data octets :filename string &optional
:media-type :dim :thumbhash), as one kind 9 message with CAPTION.  SERVER
overrides the chat's endpoints.  Returns the published kind 445 event."
  (let* ((mls (marmot-group-mls mg))
         (servers (or (%media-endpoints mg server)
                      (marmot-fail "this chat has no media policy; give a Blossom server")))
         (secret (media-secret mls))
         (tags (loop for f in files
                     collect (multiple-value-bind (att ct)
                                 (encrypt-media secret (getf f :data)
                                                (or (getf f :media-type) (guess-media-type (getf f :filename)))
                                                (getf f :filename))
                               (imeta-tag (list* :locators (list (cons +blossom-locator+ (%upload-blob acct servers ct)))
                                                 :dim (getf f :dim) :thumbhash (getf f :thumbhash)
                                                 att))))))
    (send-message acct mg caption :tags tags)))

(defun message-attachments (tags)
  "The attachments of a message with TAGS, in order: each a plist from
PARSE-IMETA, or (:rejected reason) for a reference that failed validation."
  (loop for tg in (message-imeta-tags tags)
        collect (multiple-value-bind (att why) (parse-imeta tg)
                  (or att (list :rejected why)))))

(defun %blob-urls (mg att)
  "Where to look for ATT's ciphertext, in order: its blossom locators whose URL
does not name a different hash, then each policy endpoint's fallback URL."
  (let ((hash (string-downcase (getf att :ciphertext-sha256)))
        (allowed (or (group-media-policy (marmot-group-mls mg)) (list +blossom-locator+))))
    (remove-duplicates
     (append (loop for (kind . url) in (getf att :locators)
                   when (and (string= kind +blossom-locator+) (member kind allowed :test #'string=)
                             (let ((named (%url-hash url))) (or (null named) (string= named hash))))
                     collect url)
             (mapcar (lambda (server) (blossom:blossom-url server hash)) (%media-endpoints mg)))
     :test #'string= :from-end t)))

(defun %url-hash (url)
  "The 64-hex content hash in a Blossom URL's last path segment, if it has one."
  (let* ((path (subseq url (1+ (or (position #\/ url :from-end t) -1))))
         (base (subseq path 0 (or (position #\. path) (length path)))))
    (and (= (length base) 64) (every (lambda (c) (digit-char-p c 16)) base) (string-downcase base))))

(defun fetch-media (mg message index)
  "Download, check and decrypt attachment INDEX (from 0) of MESSAGE, a message
plist of MG.  Returns (values plaintext attachment)."
  (let* ((atts (message-attachments (getf message :tags)))
         (att (or (nth index atts) (marmot-fail "message has no attachment ~D" index)))
         (secret (message-media-secret mg message)))
    (when (getf att :rejected) (marmot-fail "attachment ~D is invalid: ~A" index (getf att :rejected)))
    (unless secret (marmot-fail "the media key for epoch ~D is no longer held" (getf message :epoch)))
    (let ((tried '()))
      (dolist (url (%blob-urls mg att))
        (if (not (%contactable-url-p url))
            (push (format nil "~A: not contacted (loopback)" url) tried)
            (let ((f (blossom:blossom-fetch url :expect (string-downcase (getf att :ciphertext-sha256)))))
              (if (blossom:fetch-ok-p f)
                  (return-from fetch-media
                    (values (decrypt-media secret att (coerce-octets (blossom:fetch-bytes f))) att))
                  (push (format nil "~A: ~A" url (or (blossom:fetch-error f) (blossom:fetch-status f))) tried)))))
      (marmot-fail "attachment not available~{~%  ~A~}" (reverse tried)))))
