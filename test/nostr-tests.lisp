;;;; nostr-tests.lisp — NIP-01 ids, NIP-44 v2 vectors, NIP-59 round trip

(in-package #:cl-marmot/test)

(deftest sha1-vectors ()
  ;; FIPS 180 / RFC 3174
  (is-hex "a9993e364706816aba3e25717850c26c9cd0d89d" (sha1 (string->utf8 "abc")))
  (is-hex "da39a3ee5e6b4b0d3255bfef95601890afd80709" (sha1 (make-octets 0)))
  (is-hex "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
          (sha1 (string->utf8 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))
  ;; RFC 6455 §1.3 handshake example
  (is-equal "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
            (octets->base64 (sha1 (string->utf8 "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))))

(deftest nostr-event-id ()
  ;; foundation/application-messages.md, the kind 1210 group_disbanded example
  (let ((ev (make-unsigned-event
             :pubkey "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
             :created-at 1700000000 :kind 1210
             :tags '(("system" "group_disbanded"))
             :content "{\"v\":1,\"system_type\":\"group_disbanded\",\"text\":\"Group disbanded\",\"data\":{\"actor\":\"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"}}")))
    (is-equal "126e47076e4d0a75ed260b279c33ed433acd764fc80e2de2e0315a64116d1f52" (nostr-event-id ev)))
  ;; account-identity-proof-v2.md signing vector (secret key 3, aux zero)
  (let* ((sk (int->octets-be 3 32))
         (ev (make-nostr-event :pubkey (octets->hex (secp256k1-xonly-pubkey sk)) :created-at 1700000000
                               :kind 450
                               :tags '(("d" "marmot.account-identity-proof.v2") ("component" "0x8009")
                                       ("ciphersuite" "0x0001") ("signature_scheme" "0x0807")
                                       ("mls_signature_key" "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
                               :content "Authorize this MLS leaf key for my Marmot account")))
    (is-equal "b7e9a15dd85990fb0f49c33db3cc9875f73986207b038404ceb6b7fec4e0af6b" (compute-event-id ev))
    (sign-event ev sk)
    (is (verify-event ev))
    (let ((round (json->event (event->json ev) :require-sig t)))
      (is (verify-event round))
      (setf (nostr-event-content round) "tampered")
      (is (not (verify-event round))))))

(defun nip44-vectors ()
  (let ((path "/home/claude/marmot-ref/nip44.vectors.json"))
    (when (probe-file path)
      (with-open-file (in path :external-format :utf-8)
        (let* ((text (make-string (file-length in)))
               (n (read-sequence text in)))
          (jget (parse-json (subseq text 0 n)) "v2"))))))

(deftest nip44-vectors ()
  (let ((v (nip44-vectors)))
    (is v "vector file present")
    (when v
      (let ((valid (jget v "valid")) (invalid (jget v "invalid")))
        (loop for x across (jget valid "get_conversation_key")
              do (is-hex (jget x "conversation_key") (nip44-conversation-key (jhex x "sec1") (jget x "pub2"))))
        (loop for x across (jget valid "calc_padded_len")
              do (is-equal (aref x 1) (nip44-padded-length (aref x 0))))
        (loop for x across (jget valid "encrypt_decrypt")
              do (let ((ck (nip44-conversation-key (jhex x "sec1")
                                                   (secp256k1-xonly-pubkey (jhex x "sec2")))))
                   (is-hex (jget x "conversation_key") ck)
                   (is-equal (jget x "payload") (nip44-encrypt (jget x "plaintext") ck :nonce (jhex x "nonce")))
                   (is-equal (jget x "plaintext") (nip44-decrypt (jget x "payload") ck))))
        (loop for x across (jget valid "encrypt_decrypt_long_msg")
              do (let* ((pt (with-output-to-string (s)
                              (dotimes (i (jget x "repeat")) (write-string (jget x "pattern") s))))
                        (payload (nip44-encrypt pt (jhex x "conversation_key") :nonce (jhex x "nonce"))))
                   (is-hex (jget x "plaintext_sha256") (sha256 (string->utf8 pt)))
                   (is-hex (jget x "payload_sha256") (sha256 (string->utf8 payload)))))
        (loop for x across (jget invalid "decrypt")
              do (signals nostr-error (nip44-decrypt (jget x "payload") (jhex x "conversation_key"))
                          (jget x "note")))
        (loop for len across (jget invalid "encrypt_msg_lengths")
              do (signals nostr-error
                          (nip44-encrypt (make-string len :initial-element #\a) (make-octets 32 :initial-element 1))))))))

(deftest nip59-roundtrip ()
  (let* ((alice (generate-nostr-key))
         (bob (generate-nostr-key))
         (bob-pub (octets->hex (secp256k1-xonly-pubkey bob)))
         (rumor (make-unsigned-event :pubkey (secp256k1-xonly-pubkey alice) :kind 444
                                     :tags '(("e" "00") ("relays" "ws://x"))
                                     :content "hello"))
         (wrap (gift-wrap rumor alice bob-pub)))
    (is (verify-event wrap))
    (is-equal bob-pub (event-tag-value wrap "p"))
    (multiple-value-bind (r seal) (gift-unwrap (json->event (event->json wrap) :require-sig t) bob)
      (is-equal "hello" (nostr-event-content r))
      (is-equal 444 (nostr-event-kind r))
      (is-equal (octets->hex (secp256k1-xonly-pubkey alice)) (nostr-event-pubkey seal))
      (is (null (nostr-event-sig r))))
    (signals nostr-error (gift-unwrap wrap alice) "not addressed to alice")))
