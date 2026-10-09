;;;; crypto-tests.lisp — official test vectors for src/crypto/

(in-package #:cl-marmot/test)

(defun %ct-ascii (string) (string->utf8 string))

;;; ------------------------------------------------------------------ SHA-2
;;; FIPS 180-2 Appendices B/C/D examples ("abc", the 448-bit and 896-bit
;;; two-block messages, one million "a") plus the empty message.

(defparameter *%ct-msg448* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
(defparameter *%ct-msg896*
  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")

(deftest sha256-vectors ()
  (is-hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
          (sha256 (%ct-ascii "abc")))
  (is-hex "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
          (sha256 (make-octets 0)))
  (is-hex "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
          (sha256 (%ct-ascii *%ct-msg448*)))
  (is-hex "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
          (sha256 (%ct-ascii *%ct-msg896*)))
  (is-hex "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
          (sha256 (make-octets 1000000 :initial-element 97))))

(deftest sha512-vectors ()
  (is-hex "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
          (sha512 (%ct-ascii "abc")))
  (is-hex "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
          (sha512 (make-octets 0)))
  (is-hex "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
          (sha512 (%ct-ascii *%ct-msg448*)))
  (is-hex "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
          (sha512 (%ct-ascii *%ct-msg896*))))

(deftest sha384-vectors ()
  (is-hex "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
          (sha384 (%ct-ascii "abc")))
  (is-hex "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
          (sha384 (make-octets 0)))
  (is-hex "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
          (sha384 (%ct-ascii *%ct-msg448*)))
  (is-hex "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
          (sha384 (%ct-ascii *%ct-msg896*))))

(deftest sha2-block-boundaries ()
  ;; Lengths around the padding boundaries (55/56/63/64 and 111/112/127/128)
  ;; must agree with hashing the same bytes as a non-simple vector input.
  (dolist (n '(55 56 63 64 65 111 112 119 120 127 128 129))
    (let ((m (make-octets n :initial-element 97)))
      (is (= 32 (length (sha256 m))))
      (is (octets= (sha512 m) (sha512 (coerce m 'list)))))))

;;; ------------------------------------------------------------------ HMAC
;;; RFC 4231 section 4: test cases 1-4, 6, 7.

(defparameter *%ct-rfc4231*
  ;; (key-hex data hmac-sha256 hmac-sha512)
  (list
   (list "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" (%ct-ascii "Hi There")
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
         "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
   (list "4a656665" (%ct-ascii "what do ya want for nothing?")
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
         "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")
   (list (make-string 40 :initial-element #\a) (make-octets 50 :initial-element #xdd)
         "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
         "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb")
   (list "0102030405060708090a0b0c0d0e0f10111213141516171819"
         (make-octets 50 :initial-element #xcd)
         "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
         "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd")
   (list (make-string 262 :initial-element #\a)
         (%ct-ascii "Test Using Larger Than Block-Size Key - Hash Key First")
         "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
         "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")
   (list (make-string 262 :initial-element #\a)
         (%ct-ascii "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.")
         "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
         "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58")))

(deftest hmac-rfc4231 ()
  (loop for (key data h256 h512) in *%ct-rfc4231*
        for i from 1
        do (is-hex h256 (hmac-sha256 (hex key) data) (format nil "HMAC-SHA-256 case ~D" i))
           (is-hex h512 (hmac-sha512 (hex key) data) (format nil "HMAC-SHA-512 case ~D" i))))

;;; ------------------------------------------------------------------ HKDF
;;; RFC 5869 Appendix A, test cases 1-3 (SHA-256).

(deftest hkdf-rfc5869 ()
  (let ((prk (hkdf-extract (hex "000102030405060708090a0b0c")
                           (hex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))))
    (is-hex "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5" prk)
    (is-hex "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            (hkdf-expand prk (hex "f0f1f2f3f4f5f6f7f8f9") 42)))
  (flet ((seq-from (start)
           (let ((v (make-octets 80)))
             (dotimes (i 80 v) (setf (aref v i) (+ start i))))))
    (let ((prk (hkdf-extract (seq-from #x60) (seq-from 0))))
      (is-hex "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244" prk)
      (is-hex "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
              (hkdf-expand prk (seq-from #xb0) 82))))
  (let ((ikm (hex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")))
    (dolist (salt (list nil (make-octets 0)))
      (let ((prk (hkdf-extract salt ikm)))
        (is-hex "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04" prk)
        (is-hex "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
                (hkdf-expand prk (make-octets 0) 42))))))

;;; ------------------------------------------------------------------ ChaCha20 / Poly1305
;;; RFC 8439 sections 2.4.2, 2.5.2 and 2.8.2.

(defparameter *%ct-sunscreen*
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")

(deftest chacha20-rfc8439 ()
  (let ((key (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
        (nonce (hex "000000000000004a00000000"))
        (ct "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"))
    (is-hex ct (chacha20-xor key nonce (%ct-ascii *%ct-sunscreen*) :counter 1))
    (is (octets= (%ct-ascii *%ct-sunscreen*) (chacha20-xor key nonce (hex ct) :counter 1)))))

(deftest poly1305-rfc8439 ()
  (is-hex "a8061dc1305136c6c22b8baf0c0127a9"
          (poly1305 (hex "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                    (%ct-ascii "Cryptographic Forum Research Group"))))

(deftest chacha20-poly1305-rfc8439 ()
  (let* ((key (hex "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
         (nonce (hex "070000004041424344454647"))
         (aad (hex "50515253c0c1c2c3c4c5c6c7"))
         (pt (%ct-ascii *%ct-sunscreen*))
         (expected (concatenate 'string
                                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
                                "1ae10b594f09e26a7e902ecbd0600691"))
         (sealed (chacha20-poly1305-encrypt key nonce pt aad)))
    (is-hex expected sealed)
    (is (octets= pt (chacha20-poly1305-decrypt key nonce sealed aad)))
    (let ((bad (copy-seq sealed)))
      (setf (aref bad (1- (length bad))) (logxor 1 (aref bad (1- (length bad)))))
      (signals aead-error (chacha20-poly1305-decrypt key nonce bad aad)))
    (let ((bad (copy-seq sealed)))
      (setf (aref bad 0) (logxor #x80 (aref bad 0)))
      (signals aead-error (chacha20-poly1305-decrypt key nonce bad aad)))
    (signals aead-error (chacha20-poly1305-decrypt key nonce sealed (hex "50515253")))
    (signals aead-error (chacha20-poly1305-decrypt key nonce (make-octets 15) aad))
    (is (octets= (make-octets 0)
                 (chacha20-poly1305-decrypt key nonce
                                            (chacha20-poly1305-encrypt key nonce (make-octets 0) nil)
                                            nil)))))

;;; ------------------------------------------------------------------ AES-GCM
;;; McGrew & Viega, "The Galois/Counter Mode of Operation", Appendix B,
;;; test cases 1-4 (AES-128) and 13-16 (AES-256).

(defparameter *%ct-gcm-p*
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")

(defparameter *%ct-gcm-vectors*
  ;; (case key iv plaintext aad ciphertext tag)
  `((1 "00000000000000000000000000000000" "000000000000000000000000" "" ""
     "" "58e2fccefa7e3061367f1d57a4e7455a")
    (2 "00000000000000000000000000000000" "000000000000000000000000"
     "00000000000000000000000000000000" ""
     "0388dace60b6a392f328c2b971b2fe78" "ab6e47d42cec13bdf53a67b21257bddf")
    (3 "feffe9928665731c6d6a8f9467308308" "cafebabefacedbaddecaf888" ,*%ct-gcm-p* ""
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
     "4d5c2af327cd64a62cf35abd2ba6fab4")
    (4 "feffe9928665731c6d6a8f9467308308" "cafebabefacedbaddecaf888" ,(subseq *%ct-gcm-p* 0 120)
     "feedfacedeadbeeffeedfacedeadbeefabaddad2"
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
     "5bc94fbc3221a5db94fae95ae7121a47")
    (13 "0000000000000000000000000000000000000000000000000000000000000000" "000000000000000000000000"
     "" "" "" "530f8afbc74536b9a963b4f1c4cb738b")
    (14 "0000000000000000000000000000000000000000000000000000000000000000" "000000000000000000000000"
     "00000000000000000000000000000000" ""
     "cea7403d4d606b6e074ec5d3baf39d18" "d0d1c8a799996bf0265b98b5d48ab919")
    (15 "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308" "cafebabefacedbaddecaf888"
     ,*%ct-gcm-p* ""
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
     "b094dac5d93471bdec1a502270e3cc6c")
    (16 "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308" "cafebabefacedbaddecaf888"
     ,(subseq *%ct-gcm-p* 0 120) "feedfacedeadbeeffeedfacedeadbeefabaddad2"
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
     "76fc6ece0f4e1768cddf8853bb2d551b")))

(deftest aes-gcm-mcgrew-viega ()
  (loop for (n key iv pt aad ct tag) in *%ct-gcm-vectors*
        do (let ((sealed (aes-gcm-encrypt (hex key) (hex iv) (hex pt) (hex aad))))
             (is-hex (concatenate 'string ct tag) sealed (format nil "GCM test case ~D seal" n))
             (is (octets= (hex pt) (aes-gcm-decrypt (hex key) (hex iv) sealed (hex aad)))
                 (format nil "GCM test case ~D open" n))
             (let ((bad (copy-seq sealed)))
               (setf (aref bad 0) (logxor 1 (aref bad 0)))
               (signals aead-error (aes-gcm-decrypt (hex key) (hex iv) bad (hex aad))
                        (format nil "GCM test case ~D tamper" n))))))

(deftest aes-gcm-tamper ()
  (let* ((key (hex "feffe9928665731c6d6a8f9467308308"))
         (iv (hex "cafebabefacedbaddecaf888"))
         (aad (hex "feedfacedeadbeeffeedfacedeadbeefabaddad2"))
         (sealed (aes-gcm-encrypt key iv (hex *%ct-gcm-p*) aad)))
    (signals aead-error (aes-gcm-decrypt key iv sealed (make-octets 0)))
    (signals aead-error (aes-gcm-decrypt key (hex "cafebabefacedbaddecaf889") sealed aad))
    (signals aead-error (aes-gcm-decrypt key iv (subseq-octets sealed 0 10) aad))
    (let ((bad (copy-seq sealed)))
      (setf (aref bad (1- (length bad))) (logxor #x40 (aref bad (1- (length bad)))))
      (signals aead-error (aes-gcm-decrypt key iv bad aad)))))

(deftest aes-fips197 ()
  ;; FIPS 197 Appendix C.1 / C.3 example vectors.
  (is-hex "69c4e0d86a7b0430d8cdb78070b4c55a"
          (aes-encrypt (hex "000102030405060708090a0b0c0d0e0f")
                       (hex "00112233445566778899aabbccddeeff")))
  (is-hex "8ea2b7ca516745bfeafc49904b496089"
          (aes-encrypt (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                       (hex "00112233445566778899aabbccddeeff"))))

;;; ------------------------------------------------------------------ X25519
;;; RFC 7748 sections 5.2 and 6.1.

(deftest x25519-rfc7748 ()
  (is-hex "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
          (x25519 (hex "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                  (hex "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")))
  (is-hex "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
          (x25519 (hex "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
                  (hex "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")))
  (let ((k (hex "0900000000000000000000000000000000000000000000000000000000000000"))
        (u (hex "0900000000000000000000000000000000000000000000000000000000000000")))
    (loop for i from 1 to 1000
          do (psetf k (x25519 k u) u k)
             (when (= i 1)
               (is-hex "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079" k)))
    (is-hex "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51" k))
  (let ((a (hex "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        (b (hex "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")))
    (is-hex "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" (x25519-base a))
    (is-hex "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f" (x25519-base b))
    (is-hex "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
            (x25519 a (x25519-base b)))
    (is-hex "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
            (x25519 b (x25519-base a)))
    ;; u = 0 and u = 1 are low-order points: the all-zero result must signal.
    (signals crypto-error (x25519 a (make-octets 32)))
    (signals crypto-error (x25519 a (int->octets-le 1 32)))))

;;; ------------------------------------------------------------------ Ed25519
;;; RFC 8032 section 7.1: TEST 1, 2, 3, 1024 and SHA(abc).

(defparameter *%ct-ed25519-vectors*
  ;; (name seed public message signature)
  '(("TEST 1" "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" ""
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    ("TEST 2" "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c" "72"
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    ("TEST 3" "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025" "af82"
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")
    ("TEST SHA(abc)" "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704")))

(deftest ed25519-rfc8032 ()
  (loop for (name seed pub msg sig) in *%ct-ed25519-vectors*
        do (let ((seed (hex seed)) (msg (hex msg)))
             (is-hex pub (ed25519-public-key seed) (format nil "~A public key" name))
             (is-hex sig (ed25519-sign seed msg) (format nil "~A signature" name))
             (is (ed25519-verify (hex pub) msg (hex sig)) (format nil "~A verifies" name))
             (let ((bad (hex sig)))
               (setf (aref bad 5) (logxor 4 (aref bad 5)))
               (is (not (ed25519-verify (hex pub) msg bad)) (format nil "~A flipped R bit" name)))
             (let ((bad (hex sig)))
               (setf (aref bad 40) (logxor 1 (aref bad 40)))
               (is (not (ed25519-verify (hex pub) msg bad)) (format nil "~A flipped S bit" name)))
             (let ((bad (concat-octets msg (octets 0))))
               (is (not (ed25519-verify (hex pub) bad (hex sig))) (format nil "~A changed message" name))))))

(deftest ed25519-malformed ()
  (let ((pub (hex "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
        (sig (hex "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")))
    (is (not (ed25519-verify pub (make-octets 0) (subseq-octets sig 0 63))))
    (is (not (ed25519-verify (subseq-octets pub 0 31) (make-octets 0) sig)))
    (is (not (ed25519-verify nil nil nil)))
    (is (not (ed25519-verify "not octets" (make-octets 0) sig)))
    ;; S >= L must be rejected (add L to S).
    (let* ((s (octets->int-le sig :start 32 :end 64))
           (bad (concat-octets (subseq-octets sig 0 32)
                               (int->octets-le (+ s cl-marmot::+ed25519-l+) 32))))
      (is (not (ed25519-verify pub (make-octets 0) bad))))
    ;; A public key with y >= p is not a valid encoding.
    (is (not (ed25519-verify (make-octets 32 :initial-element #xff) (make-octets 0) sig)))))

;;; ------------------------------------------------------------------ BIP-340

;;; BIP-340 test vectors, every row of
;;; https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
;;; (index secret-key public-key aux-rand message signature verify-result comment)
(defparameter *%ct-bip340-vectors*
  '(
    (0 "0000000000000000000000000000000000000000000000000000000000000003"
       "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
       "0000000000000000000000000000000000000000000000000000000000000000"
       "0000000000000000000000000000000000000000000000000000000000000000"
       "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
       t "")
    (1 "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
       "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
       "0000000000000000000000000000000000000000000000000000000000000001"
       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
       "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"
       t "")
    (2 "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"
       "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"
       "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906"
       "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"
       "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"
       t "")
    (3 "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"
       "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
       "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"
       t "test fails if msg is reduced modulo p or n")
    (4 ""
       "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9"
       ""
       "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703"
       "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4"
       t "")
    (5 ""
       "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"
       ""
       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
       "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
       nil "public key not on the curve")
    (6 ""
       "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
       ""
       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
       "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2"
       nil "has_even_y(R) is false")
    (7 ""
       "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
       ""
       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
       "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD"
       nil "negated message")
    (8 ""
       "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
       ""
       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
       "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6"
       nil "negated s value")
    (9 ""
       "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
       ""
       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
       "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051"
       nil "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0")
    (10 ""
       "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
       ""
       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
       "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197"
       nil "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1")
    (11 ""
       "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
       ""
       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
       "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
       nil "sig[0:32] is not an X coordinate on the curve")
    (12 ""
       "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
       ""
       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
       nil "sig[0:32] is equal to field size")
    (13 ""
       "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
       ""
       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
       "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
       nil "sig[32:64] is equal to curve order")
    (14 ""
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
       ""
       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
       "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
       nil "public key is not a valid X coordinate because it exceeds the field size")
    (15 "0340034003400340034003400340034003400340034003400340034003400340"
       "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
       "0000000000000000000000000000000000000000000000000000000000000000"
       ""
       "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63"
       t "message of size 0 (added 2022-12)")
    (16 "0340034003400340034003400340034003400340034003400340034003400340"
       "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
       "0000000000000000000000000000000000000000000000000000000000000000"
       "11"
       "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF"
       t "message of size 1 (added 2022-12)")
    (17 "0340034003400340034003400340034003400340034003400340034003400340"
       "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
       "0000000000000000000000000000000000000000000000000000000000000000"
       "0102030405060708090A0B0C0D0E0F1011"
       "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5"
       t "message of size 17 (added 2022-12)")
    (18 "0340034003400340034003400340034003400340034003400340034003400340"
       "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
       "0000000000000000000000000000000000000000000000000000000000000000"
       "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"
       "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367"
       t "message of size 100 (added 2022-12)")
    ))

(deftest bip340-vectors ()
  (loop for (index sk pk aux msg sig expected comment) in *%ct-bip340-vectors*
        do (let ((pk (hex pk)) (msg (hex msg)) (sig (hex sig)))
             (when (plusp (length sk))
               (is-hex (string-downcase (octets->hex pk)) (secp256k1-xonly-pubkey (hex sk))
                       (format nil "BIP-340 row ~D public key" index))
               (is-hex (octets->hex sig) (bip340-sign (hex sk) msg (hex aux))
                       (format nil "BIP-340 row ~D signature" index)))
             (is (eq expected (bip340-verify pk msg sig))
                 (format nil "BIP-340 row ~D verify => ~A (~A)" index expected comment)))))

(deftest bip340-marmot-fixture ()
  ;; The Marmot fixture: secret key 3, all-zero aux.
  (let ((sk (int->octets-be 3 32))
        (msg (hex "b7e9a15dd85990fb0f49c33db3cc9875f73986207b038404ceb6b7fec4e0af6b")))
    (is-hex "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
            (secp256k1-xonly-pubkey sk))
    (is-hex "c5315d3c85b9d4907cb03395a2a97b3ba2eab393f8e45b13a5d5233acedac60a51d2a295e1b1b5ee372d18a49bdb8041a7dba9dedce722c7c6f712f78bbdfb5d"
            (bip340-sign sk msg (make-octets 32)))
    (is (bip340-verify (secp256k1-xonly-pubkey sk) msg
                       (hex "c5315d3c85b9d4907cb03395a2a97b3ba2eab393f8e45b13a5d5233acedac60a51d2a295e1b1b5ee372d18a49bdb8041a7dba9dedce722c7c6f712f78bbdfb5d")))))

(deftest bip340-random-and-malformed ()
  (let* ((sk (loop for k = (random-octets 32) when (secp256k1-valid-seckey-p k) return k))
         (pk (secp256k1-xonly-pubkey sk))
         (msg (random-octets 32))
         (sig (bip340-sign sk msg)))
    (is (= 64 (length sig)))
    (is (bip340-verify pk msg sig))
    (is (not (bip340-verify pk (sha256 msg) sig)))
    (is (not (bip340-verify pk msg (subseq-octets sig 0 63))))
    (is (not (bip340-verify (subseq-octets pk 0 31) msg sig)))
    (is (not (bip340-verify nil msg sig)))
    (is (not (bip340-verify pk nil sig)))
    (is (not (bip340-verify pk msg "zz")))
    (signals crypto-error (bip340-sign (make-octets 32) msg))
    (signals crypto-error (secp256k1-xonly-pubkey (make-octets 31)))))

(deftest secp256k1-key-validity ()
  (let ((n #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
        (p (- (expt 2 256) (expt 2 32) 977)))
    (is (not (secp256k1-valid-seckey-p (make-octets 32))))
    (is (secp256k1-valid-seckey-p (int->octets-be 1 32)))
    (is (secp256k1-valid-seckey-p (int->octets-be (1- n) 32)))
    (is (not (secp256k1-valid-seckey-p (int->octets-be n 32))))
    (is (not (secp256k1-valid-seckey-p (make-octets 31 :initial-element 1))))
    (is (not (secp256k1-valid-seckey-p nil)))
    (is (secp256k1-valid-xonly-p (hex "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")))
    ;; x = p and the "not on the curve" key from BIP-340 row 5.
    (is (not (secp256k1-valid-xonly-p (int->octets-be p 32))))
    (is (not (secp256k1-valid-xonly-p (hex "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34"))))
    (is (not (secp256k1-valid-xonly-p (make-octets 33))))))

;;; ------------------------------------------------------------------ secp256k1 ECDH (NIP-44 v2)

;;; NIP-44 v2 get_conversation_key vectors: the first 8 rows of
;;; v2.valid.get_conversation_key in https://github.com/paulmillr/nip44 nip44.vectors.json
;;; (sec1 pub2 conversation-key)
(defparameter *%ct-nip44-conversation-keys*
  '(
    ("315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268"
     "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133"
     "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1")
    ("a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e"
     "03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800"
     "4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b")
    ("98a5902fd67518a0c900f0fb62158f278f94a21d6f9d33d30cd3091195500311"
     "aae65c15f98e5e677b5050de82e3aba47a6fe49b3dab7863cf35d9478ba9f7d1"
     "9c00b769d5f54d02bf175b7284a1cbd28b6911b06cda6666b2243561ac96bad7")
    ("86ae5ac8034eb2542ce23ec2f84375655dab7f836836bbd3c54cefe9fdc9c19f"
     "59f90272378089d73f1339710c02e2be6db584e9cdbe86eed3578f0c67c23585"
     "19f934aafd3324e8415299b64df42049afaa051c71c98d0aa10e1081f2e3e2ba")
    ("2528c287fe822421bc0dc4c3615878eb98e8a8c31657616d08b29c00ce209e34"
     "f66ea16104c01a1c532e03f166c5370a22a5505753005a566366097150c6df60"
     "c833bbb292956c43366145326d53b955ffb5da4e4998a2d853611841903f5442")
    ("49808637b2d21129478041813aceb6f2c9d4929cd1303cdaf4fbdbd690905ff2"
     "74d2aab13e97827ea21baf253ad7e39b974bb2498cc747cdb168582a11847b65"
     "4bf304d3c8c4608864c0fe03890b90279328cd24a018ffa9eb8f8ccec06b505d")
    ("af67c382106242c5baabf856efdc0629cc1c5b4061f85b8ceaba52aa7e4b4082"
     "bdaf0001d63e7ec994fad736eab178ee3c2d7cfc925ae29f37d19224486db57b"
     "a3a575dd66d45e9379904047ebfb9a7873c471687d0535db00ef2daa24b391db")
    ("0e44e2d1db3c1717b05ffa0f08d102a09c554a1cbbf678ab158b259a44e682f1"
     "1ffa76c5cc7a836af6914b840483726207cb750889753d7499fb8b76aa8fe0de"
     "a39970a667b7f861f100e3827f4adbf6f464e2697686fe1a81aeda817d6b8bdf")
    ))

(deftest secp256k1-ecdh-nip44 ()
  (loop for (sec pub ck) in *%ct-nip44-conversation-keys*
        do (is-hex ck (hkdf-extract (%ct-ascii "nip44-v2") (secp256k1-ecdh-x (hex sec) (hex pub)))
                   (format nil "NIP-44 conversation key for ~A" sec)))
  (dotimes (i 3)
    (let* ((a (loop for k = (random-octets 32) when (secp256k1-valid-seckey-p k) return k))
           (b (loop for k = (random-octets 32) when (secp256k1-valid-seckey-p k) return k)))
      (is (octets= (secp256k1-ecdh-x a (secp256k1-xonly-pubkey b))
                   (secp256k1-ecdh-x b (secp256k1-xonly-pubkey a)))
          "ECDH symmetry")))
  (signals crypto-error (secp256k1-ecdh-x (int->octets-be 1 32)
                                          (hex "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34")))
  (signals crypto-error (secp256k1-ecdh-x (make-octets 32)
                                          (hex "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"))))
