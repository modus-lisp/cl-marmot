;;;; cl-marmot.asd — Marmot (MLS over Nostr) in portable Common Lisp

(asdf:defsystem #:cl-marmot
  :description "A Marmot protocol client: MLS (RFC 9420) group messaging over Nostr, in portable Common Lisp."
  :license "MIT"
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "package")
     (:module "util"
      :serial t
      :components ((:file "bytes")
                   (:file "platform")
                   (:file "base64")
                   (:file "json")
                   (:file "tls-codec")))
     (:module "crypto"
      :serial t
      :components ((:file "conditions")
                   (:file "sha2")
                   (:file "hmac")
                   (:file "chacha20")
                   (:file "aes-gcm")
                   (:file "x25519")
                   (:file "ed25519")
                   (:file "secp256k1")))
     (:module "mls"
      :serial t
      :components ((:file "structs")
                   (:file "ciphersuite")
                   (:file "tree")
                   (:file "key-schedule")
                   (:file "framing")
                   (:file "group")))))))

(asdf:defsystem #:cl-marmot/test
  :depends-on (#:cl-marmot)
  :serial t
  :components
  ((:module "test"
    :serial t
    :components ((:file "harness")
                 (:file "crypto-tests")
                 (:file "util-tests")
                 (:file "mls-vector-tests")))))
