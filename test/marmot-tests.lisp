;;;; marmot-tests.lisp — Marmot components and KeyPackages

(in-package #:cl-marmot/test)

(deftest identity-proof-vector ()
  ;; app-components/account-identity-proof-v2.md signing test vector
  (let ((proof (make-identity-proof (int->octets-be 3 32)
                                    (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                                    :created-at 1700000000)))
    ;; BIP-340 signing uses fresh aux randomness, so compare the fixed parts and verify
    (is-hex "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9000000006553f100"
            (subseq-octets proof 0 40))
    (is (verify-identity-proof proof (hex "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
                               (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))))
  (is (verify-identity-proof
       (hex "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9000000006553f100c5315d3c85b9d4907cb03395a2a97b3ba2eab393f8e45b13a5d5233acedac60a51d2a295e1b1b5ee372d18a49bdb8041a7dba9dedce722c7c6f712f78bbdfb5d")
       (hex "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
       (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
      "spec component bytes verify")
  (signals marmot-error
           (verify-identity-proof
            (hex "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9000000006553f100c5315d3c85b9d4907cb03395a2a97b3ba2eab393f8e45b13a5d5233acedac60a51d2a295e1b1b5ee372d18a49bdb8041a7dba9dedce722c7c6f712f78bbdfb5d")
            (hex "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
            (make-octets 32))
           "proof bound to a different MLS key"))

(defun %fixture (name)
  (with-open-file (in (concatenate 'string (fixture-dir) name) :external-format :utf-8)
    (let* ((text (make-string (file-length in)))
           (n (read-sequence text in)))
      (subseq text 0 n))))

(deftest wn-key-package-validates ()
  ;; a real KeyPackage event published by mdk's `wn`; validated at its own time
  (let* ((ev (json->event (string-trim '(#\Newline) (%fixture "wn-keypackage-event.json")) :require-sig t))
         (kp (validate-key-package-event ev :now (ev:event-created-at ev))))
    (is (key-package-last-resort-p kp))
    (is-equal (ev:event-pubkey ev) (octets->hex (leaf-account (key-package-leaf-node kp))))))

(deftest our-key-package-validates ()
  (let* ((sk (generate-nostr-key))
         (bundle (make-marmot-key-package sk))
         (ev (key-package-event sk bundle (random-octets 32)))
         (kp (validate-key-package-event (json->event (event->json ev) :require-sig t))))
    (is (octets= (tls-serialize 'key-package kp)
                 (tls-serialize 'key-package (key-package-bundle-key-package bundle))))))

(deftest component-codecs ()
  (let ((a (hex "0202020202020202020202020202020202020202020202020202020202020202"))
        (b (hex "0101010101010101010101010101010101010101010101010101010101010101")))
    (is-equal (list b a) (decode-admin-policy (encode-admin-policy (list a b a))))
    (signals marmot-error (decode-admin-policy (hex "00"))))
  (multiple-value-bind (gid relays)
      (decode-nostr-routing (encode-nostr-routing (make-octets 32 :initial-element 7)
                                                  '("wss://b.example" "wss://a.example")))
    (is-equal 32 (length gid))
    (is-equal '("wss://a.example" "wss://b.example") relays))
  (multiple-value-bind (n d) (decode-group-profile (encode-group-profile "name" "desc"))
    (is-equal "name" n) (is-equal "desc" d))
  (is-equal :active (decode-lifecycle (encode-lifecycle :active)))
  (signals marmot-error (decode-lifecycle (octets 0 0))))

(deftest key-package-upkeep-plan ()
  (let* ((sk (generate-nostr-key))
         (acct (make-account-from-secret sk :relays '("ws://127.0.0.1:1")))
         (now 1800000000)
         (slot (random-octets 32))
         (entry (lambda (made-at)
                  (list :bundle (make-marmot-key-package sk :now made-at) :event-id "00" :ref "00" :d slot))))
    ;; nothing published: a KeyPackage is due
    (multiple-value-bind (expired refresh) (key-package-plan acct now)
      (is (null expired)) (is refresh "an account with no KeyPackage needs one"))
    ;; a fresh one (84 days left): nothing to do
    (setf (cl-marmot::account-key-packages acct) (list (funcall entry now)))
    (multiple-value-bind (expired refresh) (key-package-plan acct now)
      (is (null expired)) (is (not refresh)))
    ;; 80 days later: four days left, inside the 7-day window: refresh, same slot
    (multiple-value-bind (expired refresh d) (key-package-plan acct (+ now (* 80 24 3600)))
      (is (null expired)) (is refresh) (is (octets= d slot) "the replacement reuses the slot"))
    ;; 90 days later: expired, its keys must go, and a new one is due
    (multiple-value-bind (expired refresh) (key-package-plan acct (+ now (* 90 24 3600)))
      (is-equal 1 (length expired)) (is refresh))))
