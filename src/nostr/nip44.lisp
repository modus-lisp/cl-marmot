;;;; nip44.lisp — NIP-44 version 2 encrypted payloads, and NIP-59 gift wrap

(in-package #:cl-marmot)

(defun nip44-conversation-key (sk pubkey)
  "SK: 32 octets.  PUBKEY: 32-octet x-only key or 64-char hex."
  (hkdf-extract (string->utf8 "nip44-v2")
                (secp256k1-ecdh-x sk (if (stringp pubkey) (hex->octets pubkey) pubkey))))

(defun nip44-message-keys (conversation-key nonce)
  "Returns (values chacha-key chacha-nonce hmac-key)."
  (let ((k (hkdf-expand conversation-key nonce 76)))
    (values (subseq-octets k 0 32) (subseq-octets k 32 44) (subseq-octets k 44 76))))

(defun nip44-padded-length (n)
  (if (<= n 32)
      32
      (let* ((next-power (ash 1 (integer-length (1- n))))
             (chunk (if (<= next-power 256) 32 (floor next-power 8))))
        (* chunk (1+ (floor (1- n) chunk))))))

(defun nip44-encrypt (plaintext conversation-key &key nonce)
  "PLAINTEXT: string.  Returns the base64 payload."
  (let* ((pt (string->utf8 plaintext))
         (n (length pt)))
    (unless (<= 1 n 65535) (nostr-fail "NIP-44 plaintext length ~D out of range" n))
    (let* ((nonce (or nonce (random-octets 32)))
           (padded (make-octets (+ 2 (nip44-padded-length n)))))
      (setf (aref padded 0) (ash n -8) (aref padded 1) (logand n #xFF))
      (replace padded pt :start1 2)
      (multiple-value-bind (ck cn hk) (nip44-message-keys conversation-key nonce)
        (let* ((ct (chacha20-xor ck cn padded))
               (mac (hmac-sha256 hk (concat-octets nonce ct))))
          (octets->base64 (concat-octets (octets 2) nonce ct mac)))))))

(defun nip44-decrypt (payload conversation-key)
  "Returns the plaintext string; signals nostr-error on any failure."
  (let ((plen (length payload)))
    (when (or (zerop plen) (char= (char payload 0) #\#)) (nostr-fail "NIP-44: unsupported encoding"))
    (unless (<= 132 plen 87472) (nostr-fail "NIP-44: invalid payload size")))
  (let* ((data (handler-case (base64->octets payload)
                 (base64-error () (nostr-fail "NIP-44: invalid base64"))))
         (dlen (length data)))
    (unless (<= 99 dlen 65603) (nostr-fail "NIP-44: invalid data size"))
    (unless (= (aref data 0) 2) (nostr-fail "NIP-44: unknown version ~D" (aref data 0)))
    (let ((nonce (subseq-octets data 1 33))
          (ct (subseq-octets data 33 (- dlen 32)))
          (mac (subseq-octets data (- dlen 32))))
      (multiple-value-bind (ck cn hk) (nip44-message-keys conversation-key nonce)
        (unless (ct-octets= mac (hmac-sha256 hk (concat-octets nonce ct)))
          (nostr-fail "NIP-44: invalid MAC"))
        (let* ((padded (chacha20-xor ck cn ct))
               (n (logior (ash (aref padded 0) 8) (aref padded 1))))
          (unless (and (<= 1 n) (= (length padded) (+ 2 (nip44-padded-length n))))
            (nostr-fail "NIP-44: invalid padding"))
          (unless (every #'zerop (subseq padded (+ 2 n)))
            (nostr-fail "NIP-44: invalid padding"))
          (handler-case (utf8->string padded :start 2 :end (+ 2 n))
            (utf8-error () (nostr-fail "NIP-44: plaintext is not UTF-8"))))))))

;;; ---------------------------------------------------------------------------
;;; NIP-59 gift wrap
;;;
;;; rumor (unsigned, id set) -> kind 13 seal (signed by the author, content =
;;; NIP-44(rumor)) -> kind 1059 wrap (signed by a fresh ephemeral key, content =
;;; NIP-44(seal), one p tag).  Seal and wrap timestamps are randomised up to two
;;; days into the past, as NIP-59 recommends.

(defun %nip59-timestamp ()
  (- (unix-time) (mod (octets->int-be (random-octets 4)) (* 2 24 3600))))

(defun gift-wrap (rumor author-sk recipient-pubkey-hex &key (extra-tags '()))
  "Wrap RUMOR (an unsigned NOSTR-EVENT authored by AUTHOR-SK's key) for
RECIPIENT.  Returns the kind 1059 event."
  (let* ((seal (make-signed-event author-sk :created-at (%nip59-timestamp) :kind 13 :tags '()
                                            :content (nip44-encrypt
                                                      (event->json rumor)
                                                      (nip44-conversation-key author-sk recipient-pubkey-hex))))
         (eph (generate-nostr-key)))
    (make-signed-event eph :created-at (%nip59-timestamp) :kind 1059
                           :tags (cons (list "p" recipient-pubkey-hex) extra-tags)
                           :content (nip44-encrypt (event->json seal)
                                                   (nip44-conversation-key eph recipient-pubkey-hex)))))

(defun gift-unwrap (wrap my-sk)
  "Verify and open a kind 1059 wrap addressed to MY-SK's key.  Returns
(values rumor seal).  The rumor's pubkey is checked against the seal signer."
  (unless (= (nostr-event-kind wrap) 1059) (nostr-fail "not a gift wrap"))
  (unless (verify-event wrap) (nostr-fail "gift wrap signature"))
  (let ((me (octets->hex (secp256k1-xonly-pubkey my-sk))))
    (unless (string= (event-tag-value wrap "p") me) (nostr-fail "gift wrap is not addressed to us")))
  (let* ((seal (json->event (nip44-decrypt (nostr-event-content wrap)
                                           (nip44-conversation-key my-sk (nostr-event-pubkey wrap)))
                            :require-sig t)))
    (unless (= (nostr-event-kind seal) 13) (nostr-fail "inner event is not a seal"))
    (unless (verify-event seal) (nostr-fail "seal signature"))
    (let ((rumor (json->event (nip44-decrypt (nostr-event-content seal)
                                             (nip44-conversation-key my-sk (nostr-event-pubkey seal)))
                              :allow-sig nil)))
      (unless (string= (nostr-event-pubkey rumor) (nostr-event-pubkey seal))
        (nostr-fail "rumor author does not match the seal signer"))
      (unless (string= (nostr-event-id rumor) (compute-event-id rumor))
        (nostr-fail "rumor id mismatch"))
      (values rumor seal))))
