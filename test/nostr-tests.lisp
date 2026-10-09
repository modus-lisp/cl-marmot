;;;; nostr-tests.lisp — NIP-01 ids, NIP-44 v2 vectors, NIP-59 round trip
;;;;
;;;; These exercise cl-nostr (events, NIP-44, NIP-59): the vectors are a
;;;; conformance check of the shared library, not of code in this repository.

(in-package #:cl-marmot/test)

(deftest nostr-event-ids ()
  ;; foundation/application-messages.md, the kind 1210 group_disbanded example
  (let ((ev (make-unsigned-event
             :pubkey "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
             :created-at 1700000000 :kind 1210
             :tags '(("system" "group_disbanded"))
             :content "{\"v\":1,\"system_type\":\"group_disbanded\",\"text\":\"Group disbanded\",\"data\":{\"actor\":\"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"}}")))
    (is-equal "126e47076e4d0a75ed260b279c33ed433acd764fc80e2de2e0315a64116d1f52" (ev:event-id ev)))
  ;; account-identity-proof-v2.md signing vector (secret key 3, aux zero)
  (let* ((sk (int->octets-be 3 32))
         (ev (ev:make-event :pubkey (octets->hex (secp256k1-xonly-pubkey sk)) :created-at 1700000000
                               :kind 450
                               :tags '(("d" "marmot.account-identity-proof.v2") ("component" "0x8009")
                                       ("ciphersuite" "0x0001") ("signature_scheme" "0x0807")
                                       ("mls_signature_key" "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
                               :content "Authorize this MLS leaf key for my Marmot account")))
    (is-equal "b7e9a15dd85990fb0f49c33db3cc9875f73986207b038404ceb6b7fec4e0af6b" (compute-event-id ev))
    (setf ev (make-signed-event sk :created-at 1700000000 :kind 450 :tags (ev:event-tags ev)
                                   :content (ev:event-content ev)))
    (is (verify-event ev))
    (let ((round (json->event (event->json ev) :require-sig t)))
      (is (verify-event round))
      (setf (ev:event-content round) "tampered")
      (is (not (verify-event round))))))

(defun nip44-vectors ()
  (let ((path (require-vector-file "nip44.vectors.json")))
    (when path
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
              do (is-hex (jget x "conversation_key")
                         (nip44:conversation-key (octets->int-be (jhex x "sec1")) (jhex x "pub2"))))
        (loop for x across (jget valid "calc_padded_len")
              do (is-equal (aref x 1) (nip44:calc-padded-len (aref x 0))))
        (loop for x across (jget valid "encrypt_decrypt")
              do (let ((ck (nip44:conversation-key (octets->int-be (jhex x "sec1"))
                                                   (secp256k1-xonly-pubkey (jhex x "sec2")))))
                   (is-hex (jget x "conversation_key") ck)
                   (is-equal (jget x "payload")
                             (nip44:nip44-encrypt-with-nonce (string->utf8 (jget x "plaintext")) ck (jhex x "nonce")))
                   (is-equal (jget x "plaintext") (nip44:nip44-decrypt-ck (jget x "payload") ck))))
        (loop for x across (jget valid "encrypt_decrypt_long_msg")
              do (let* ((pt (with-output-to-string (s)
                              (dotimes (i (jget x "repeat")) (write-string (jget x "pattern") s))))
                        (payload (nip44:nip44-encrypt-with-nonce (string->utf8 pt) (jhex x "conversation_key")
                                                                 (jhex x "nonce"))))
                   (is-hex (jget x "plaintext_sha256") (sha256 (string->utf8 pt)))
                   (is-hex (jget x "payload_sha256") (sha256 (string->utf8 payload)))))
        (loop for x across (jget invalid "decrypt")
              do (signals error (nip44:nip44-decrypt-ck (jget x "payload") (jhex x "conversation_key"))
                          (jget x "note")))
        (loop for len across (jget invalid "encrypt_msg_lengths")
              do (signals error
                          (nip44:nip44-encrypt-ck (make-string len :initial-element #\a)
                                                  (make-octets 32 :initial-element 1))))))))

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
      (is-equal "hello" (ev:event-content r))
      (is-equal 444 (ev:event-kind r))
      (is-equal (octets->hex (secp256k1-xonly-pubkey alice)) (ev:event-pubkey seal))
      (is (null (ev:event-sig r))))
    (signals nostr-error (gift-unwrap wrap alice) "not addressed to alice")
    (signals nostr-error (gift-unwrap (let ((tampered (json->event (event->json wrap) :require-sig t)))
                                        (setf (ev:event-content tampered) "AAAA")
                                        tampered)
                                      bob)
             "a tampered wrap")))
