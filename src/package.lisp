;;;; package.lisp — cl-marmot
;;;;
;;;; One package for the whole library.  Layers are kept apart by file and by
;;;; name prefix rather than by package:
;;;;
;;;;   util/    bytes, hex, base64, bech32, JSON, QUIC/TLS varint codec
;;;;   crypto/  SHA-2, HMAC, HKDF, AES-GCM, ChaCha20-Poly1305, X25519,
;;;;            Ed25519, secp256k1 + BIP-340, CSPRNG
;;;;   mls/     RFC 9420 + draft-ietf-mls-extensions-10 (ciphersuite 0x0001)
;;;;   nostr/   NIP-01 events, NIP-44 v2, NIP-59, relay client
;;;;   marmot/  Marmot components, group flows, app events
;;;;   client/  account store and the interactive client
;;;;
;;;; Everything is portable ANSI Common Lisp.  The only implementation-specific
;;;; code is the socket and entropy shim in util/platform.lisp.

(defpackage #:cl-marmot
  (:use #:common-lisp)
  (:nicknames #:marmot))
