;;;; media-tests.lisp — encrypted media v2 without a network
;;;;
;;;; The protocol half of features/encrypted-media.md: media-type
;;;; canonicalization, the 0x800b policy codec, imeta build/parse, encryption,
;;;; and an attachment sent from one member and opened by another after the
;;;; group has moved on to later epochs (and after a save/load).

(in-package #:cl-marmot/test)

(deftest media-type-canonicalization ()
  (is-equal "image/jpeg" (canonical-media-type "image/jpeg"))
  (is-equal "image/jpeg" (canonical-media-type "image/jpg"))
  (is-equal "image/jpeg" (canonical-media-type " IMAGE/JPG ; q=1"))
  (is-equal "text/plain" (canonical-media-type "text/plain;charset=utf-8"))
  (is-equal "application/vnd.api+json" (canonical-media-type "application/vnd.api+json"))
  (dolist (bad (list "image" "image/" "/png" "image/png/x" "ima ge/png" "image/p(ng)" ""
                     (format nil "image/png~C" (code-char 11)) (format nil "imag~C/png" (code-char 233))))
    (is (null (canonical-media-type bad)) (format nil "~S is not a media type" bad))))

(deftest media-policy-codec ()
  (let* ((eps '(("blossom-v1" . "https://blossom.primal.net/") ("blossom-v1" . "http://127.0.0.1:3000/")))
         (bytes (encode-media-policy '("blossom-v1") eps)))
    (multiple-value-bind (kinds endpoints) (decode-media-policy bytes)
      (is-equal '("blossom-v1") kinds)
      (is-equal eps endpoints "order is kept"))
    (flet ((rejects (kinds eps what)
             (is (handler-case (progn (decode-media-policy (encode-media-policy kinds eps)) nil)
                   (marmot-error () t))
                 what)))
      (rejects '() '(("blossom-v1" . "https://a.example/")) "no locator kinds")
      (rejects '("blossom-v1") '() "no endpoints")
      (rejects '("Blossom") '(("Blossom" . "https://a.example/")) "uppercase kind")
      (rejects '("blossom-v1") '(("other" . "https://a.example/")) "endpoint kind not allowed")
      (rejects '("blossom-v1") '(("blossom-v1" . "https://a.example")) "URL not normalized (no path)")
      (rejects '("blossom-v1") '(("blossom-v1" . "https://A.example/")) "URL not normalized (case)")
      (rejects '("blossom-v1") '(("blossom-v1" . "https://a.example:443/")) "default port")
      (rejects '("blossom-v1") '(("blossom-v1" . "https://u@a.example/")) "userinfo")
      (rejects '("blossom-v1") '(("blossom-v1" . "https://a.example/?x=1")) "query")
      (rejects '("blossom-v1") '(("blossom-v1" . "ftp://a.example/")) "scheme")
      (rejects '("blossom-v1" "blossom-v1") '(("blossom-v1" . "https://a.example/")) "duplicate kind"))
    ;; a group we create carries (and requires) the default policy
    (let ((mg (create-marmot-group (generate-nostr-key) :name "m" :relays '("ws://127.0.0.1:1"))))
      (is (member +c-encrypted-media-v2+ (group-required-components (marmot-group-mls mg))))
      (is-equal (mapcar (lambda (u) (cons "blossom-v1" u)) *default-media-endpoints*)
                (nth-value 1 (group-media-policy (marmot-group-mls mg)))))))

(defun %attachment-tag (att) (imeta-tag (list* :locators '(("blossom-v1" . "https://b.example/abc")) att)))

(deftest media-encrypt-and-imeta ()
  (let* ((secret (random-octets 32))
         (data (string->utf8 "a picture, honestly")))
    (multiple-value-bind (att ct) (encrypt-media secret data "image/JPG" "cat.jpg")
      (is-equal "image/jpeg" (getf att :media-type) "the stored type is canonical")
      (is-equal (octets->hex (sha256 ct)) (getf att :ciphertext-sha256))
      (let* ((tag (%attachment-tag att))
             (parsed (parse-imeta tag)))
        (is-equal "imeta" (first tag))
        (is-equal "v encrypted-media-v2" (second tag))
        (is parsed "our own tag parses")
        (is (octets= data (decrypt-media secret parsed ct)) "round trip")
        ;; tampering: blob, key, and each authenticated field
        (let ((bad (copy-seq ct))) (setf (aref bad 0) (logxor 1 (aref bad 0)))
          (is (handler-case (progn (decrypt-media secret parsed bad) nil) (marmot-error () t)) "changed blob"))
        (is (handler-case (progn (decrypt-media (random-octets 32) parsed ct) nil) (marmot-error () t)) "wrong epoch key")
        (is (handler-case (progn (decrypt-media secret (list* :filename "dog.jpg" parsed) ct) nil) (marmot-error () t))
            "file name is in the AAD")
        ;; strict parsing: each reason is attachment-local, so parse returns NIL + why
        (flet ((rejected (tag what) (is (null (parse-imeta tag)) what)))
          (rejected (append tag (list "m image/png")) "duplicate m")
          (rejected (append tag (list "blurhash LEHV6n")) "blurhash")
          (rejected (remove "v encrypted-media-v2" tag :test #'string=) "no version")
          (rejected (substitute "v encrypted-media-v1" "v encrypted-media-v2" tag :test #'string=) "other version")
          (rejected (remove-if (lambda (f) (search "locator " f)) tag) "no locator")
          (rejected (substitute "m image/jpg" "m image/jpeg" tag :test #'string=) "non-canonical type")
          (rejected (mapcar (lambda (f) (if (search "nonce " f) "nonce 00" f)) tag) "short nonce")
          (rejected (substitute "locator blossom-v1 not a url" "locator blossom-v1 https://b.example/abc" tag
                                :test #'string=)
                    "locator is not a URL"))
        ;; unknown fields and other locator kinds are fine
        (is (parse-imeta (append tag (list "x whatever" "locator ipfs-v1 ipfs://zzz"))))
        (is-equal 2 (length (getf (parse-imeta (append tag (list "locator ipfs-v1 ipfs://zzz"))) :locators)))))))

(deftest media-across-epochs-and-restart ()
  ;; alice sends a file at epoch 1; bob opens it after two more commits and a
  ;; save/load, with the secret recorded when the message arrived
  (let* ((alice-sk (generate-nostr-key)) (bob-sk (generate-nostr-key))
         (alice-pk (secp256k1-xonly-pubkey alice-sk))
         (bob-kp (make-marmot-key-package bob-sk))
         (a (create-marmot-group alice-sk :name "media" :relays '("ws://127.0.0.1:1")))
         (st (stage-commit a :proposals (add-proposals-for (list (key-package-bundle-key-package bob-kp))))))
    (merge-pending a)
    (let ((b (join-marmot-group (mls-message-body (tls-deserialize 'mls-message (staged-commit-welcome st))) bob-kp))
          (data (random-octets 5000)))
      (multiple-value-bind (att ct) (encrypt-media (media-secret (marmot-group-mls a)) data "application/pdf" "a b.pdf")
        (%deliver b (send-app-message a alice-pk 9 "the report" :tags (list (%attachment-tag att))))
        (dotimes (i 2)
          (stage-commit a)
          (let ((env (%commit-envelope a))) (merge-pending a) (%deliver b env)))
        (is-equal 3 (mg-epoch b))
        (let* ((b2 (%roundtrip-group b))   ; messages live in the message log, not the group sexp
               (m (find "the report" (marmot-group-messages b) :key (lambda (p) (getf p :content)) :test #'equal))
               (secret (message-media-secret b2 m))
               (parsed (first (message-attachments (getf m :tags)))))
          (is secret "the epoch-1 media secret survived the epoch changes and the restart")
          (is-equal "a b.pdf" (getf parsed :filename) "file names may contain spaces")
          (is (octets= data (decrypt-media secret parsed ct)) "bob opens the file")
          ;; and alice can open her own
          (let ((own (find "the report" (marmot-group-messages a) :key (lambda (p) (getf p :content)) :test #'equal)))
            (is (octets= data (decrypt-media (message-media-secret a own) parsed ct)) "alice opens her own")))))))
