;;;; cl-marmot.asd — Marmot (MLS over Nostr) in portable Common Lisp

(asdf:defsystem #:cl-marmot
  :description "A Marmot protocol client: MLS (RFC 9420) group messaging over Nostr, in portable Common Lisp."
  :version "1.0.0"
  :author "ynniv"
  :license "MIT"
  :depends-on (#:natrium #:secp256k1-fast #:seal #:cl-nostr #:bordeaux-threads)
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
                   (:file "bridge")))
     (:module "mls"
      :serial t
      :components ((:file "structs")
                   (:file "ciphersuite")
                   (:file "tree")
                   (:file "key-schedule")
                   (:file "framing")
                   (:file "group")))
     (:module "nostr"
      :serial t
      :components ((:file "event")))
     (:module "marmot"
      :serial t
      :components ((:file "components")
                   (:file "key-packages")
                   (:file "groups")
                   (:file "convergence")))
     (:module "client"
      :serial t
      :components ((:file "account")
                   (:file "store")))
     (:file "api")
     (:file "cli")))))

(asdf:defsystem #:cl-marmot/test
  :description "cl-marmot's tests.  Run test/fetch-vectors.sh first."
  :depends-on (#:cl-marmot)
  :serial t
  :components
  ((:module "test"
    :serial t
    :components ((:file "harness")
                 (:file "crypto-tests")
                 (:file "util-tests")
                 (:file "mls-vector-tests")
                 (:file "nostr-tests")
                 (:file "marmot-tests")
                 (:file "group-tests")
                 (:file "convergence-tests")))))
