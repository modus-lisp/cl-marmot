;;;; package.lisp — cl-marmot
;;;;
;;;; One package for the whole library.  Layers are kept apart by file and by
;;;; name prefix rather than by package:
;;;;
;;;;   util/    bytes, hex, base64, JSON, QUIC/TLS varint codec
;;;;   crypto/  the crypto vocabulary MLS is written against, over natrium,
;;;;            seal and secp256k1-fast
;;;;   mls/     RFC 9420 + draft-ietf-mls-extensions-10 (ciphersuite 0x0001)
;;;;   nostr/   Marmot-strict event handling over cl-nostr (events, NIP-44,
;;;;            NIP-59, bech32 and the relay pool are cl-nostr's)
;;;;   marmot/  Marmot components, group flows, app events
;;;;   client/  account store and the interactive client
;;;;
;;;; Dependencies are the modus-lisp libraries natrium, secp256k1-fast, seal
;;;; and cl-nostr; this package reaches cl-nostr through local nicknames.

(defpackage #:cl-marmot
  (:use #:common-lisp)
  (:nicknames #:marmot)
  (:local-nicknames (#:ev #:cl-nostr.event)
                    (#:k #:cl-nostr.keys)
                    (#:b32 #:cl-nostr.bech32)
                    (#:nip44 #:cl-nostr.nip44)
                    (#:nip59 #:cl-nostr.nip59)
                    (#:pool #:cl-nostr.pool)
                    (#:flt #:cl-nostr.filter)
                    (#:nip05 #:cl-nostr.nip05)))
