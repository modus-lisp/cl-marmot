;;;; util-tests.lisp — bytes, base64, bech32, JSON, TLS codec

(in-package #:cl-marmot/test)

(deftest utf8-roundtrip ()
  (let ((s (coerce (list #\a (code-char #xE9) (code-char #x20AC) (code-char #x1F600)) 'string)))
    (is-hex "61c3a9e282acf09f9880" (string->utf8 s))
    (is-equal s (utf8->string (string->utf8 s))))
  (signals utf8-error (utf8->string (octets #xC0 #x80)) "overlong")
  (signals utf8-error (utf8->string (octets #xED #xA0 #x80)) "surrogate"))

(deftest base64-rfc4648 ()
  ;; RFC 4648 §10
  (loop for (in out) in '(("" "") ("f" "Zg==") ("fo" "Zm8=") ("foo" "Zm9v")
                          ("foob" "Zm9vYg==") ("fooba" "Zm9vYmE=") ("foobar" "Zm9vYmFy"))
        do (is-equal out (octets->base64 (string->utf8 in)))
           (is-equal in (utf8->string (base64->octets out))))
  (signals base64-error (base64->octets "Zh==") "non-zero trailing bits")
  (signals base64-error (base64->octets "Zg") "missing padding")
  (signals base64-error (base64->octets "Zm9v Yg==") "whitespace"))

(deftest bech32-nip19 ()
  ;; NIP-19 examples
  (is-equal "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
            (npub-encode (hex "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d")))
  (is-hex "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
          (npub-decode "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"))
  (is-equal "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
            (nsec-encode (hex "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa")))
  (signals bech32-error (npub-decode "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w7")))

(deftest json-roundtrip ()
  (let ((v (parse-json "{\"a\":[1,-2,\"x\\n\\u00e9\\ud83d\\ude00\"],\"b\":true,\"c\":null,\"d\":{}}")))
    (is-equal 1 (aref (jget v "a") 0))
    (is-equal (coerce (list #\x #\Newline (code-char #xE9) (code-char #x1F600)) 'string)
              (aref (jget v "a") 2))
    (is-equal :true (jget v "b"))
    (is-equal (format nil "{\"a\":[1,-2,\"x\\n~C~C\"],\"b\":true,\"c\":null,\"d\":{}}"
                      (code-char #xE9) (code-char #x1F600))
              (to-json (parse-json "{\"a\":[1,-2,\"x\\n\\u00e9\\ud83d\\ude00\"],\"b\":true,\"c\":null,\"d\":{}}"))
              "re-encoding is NIP-01 style (verbatim non-ASCII)")))

(deftest json-nip01-escaping ()
  (is-equal (format nil "\"a\\\"b\\\\c\\nd\\te~C\"" (code-char #xE9))
            (to-json (format nil "a\"b\\c~Cd~Ce~C" #\Newline #\Tab (code-char #xE9))))
  (signals json-error (parse-json "{\"a\":1,\"a\":2}" :reject-duplicate-keys t))
  (signals json-error (parse-json "[1,2] x")))

(deftest tls-varint ()
  ;; RFC 9420 §2.1.2 / canonical-encoding.md examples
  (is-hex "00" (with-writer (w) (w-varint w 0)))
  (is-hex "25" (with-writer (w) (w-varint w 37)))
  (is-hex "7bbd" (with-writer (w) (w-varint w 15293)))
  (is-hex "9d7f3e7d" (with-writer (w) (w-varint w 494878333)))
  (is-hex "c2197c5eff14e88c" (with-writer (w) (w-varint w 151288809941952652 :quic t)))
  (is-equal 15293 (r-varint (make-reader (hex "7bbd"))))
  (signals decode-error (r-varint (make-reader (hex "4025"))) "non-minimal")
  (signals decode-error (r-varint (make-reader (hex "c2197c5eff14e88c"))) "8-byte in MLS")
  (is-hex "0709026222375a36" (with-writer (w) (w-opaque w (hex "09026222375a36"))))
  (let ((r (make-reader (hex "050102030a0b"))))
    (is-equal '(1 2 3 10 11) (r-vector r #'r-u8))
    (is (reader-done-p r))))
