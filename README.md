# cl-marmot

A [Marmot](https://github.com/marmot-protocol/marmot) client in portable Common Lisp: end-to-end encrypted group
messaging with MLS ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)) over Nostr relays, the protocol
[White Noise](https://github.com/marmot-protocol/whitenoise-linux) speaks.

cl-marmot implements MLS ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) with the extensions draft Marmot uses)
and the Marmot protocol in plain Common Lisp, on the [modus-lisp](https://github.com/modus-lisp) libraries:

| library | provides |
|---|---|
| [natrium](https://github.com/modus-lisp/natrium) | SHA-2, HMAC, HKDF, ChaCha20-Poly1305, X25519, Ed25519, CSPRNG (constant-time secret paths) |
| [secp256k1-fast](https://github.com/modus-lisp/secp256k1-fast) | BIP-340 Schnorr |
| [seal](https://github.com/modus-lisp/seal) | AES-GCM, and TLS 1.3 with certificate validation for `wss://` relays |
| [cl-nostr](https://github.com/modus-lisp/cl-nostr) | NIP-01 events, NIP-19, NIP-44, NIP-59, the relay pool |

cl-nostr in turn uses a few Quicklisp systems (ironclad, cl-base64, jzon, bordeaux-threads). `load-deps.lisp` finds the
modus-lisp checkouts (`$MODUS_LISP`, `../modus-lisp` or `~/modus-lisp`) and Quicklisp. Marmot's Welcome travels as a
kind-444 NIP-59 rumor, which needs cl-nostr's `wrap-rumor`/`unwrap-rumor` (branch `marmot-rumors`).

## Status

It interoperates with mdk's `wn`, the engine whitenoise-linux links through `marmot-c`
(`test/interop/run-wn-interop.sh`, **22 of 22** steps, fresh relay and accounts each run):

| | |
|---|---|
| join a group created by `wn` from its Welcome | ✓ |
| messages in both directions (kind 9 app events in MLS PrivateMessages, kind 445 envelopes) | ✓ |
| apply `wn`'s commits: rename (AppDataUpdate), remove us | ✓ |
| create a group `wn` joins; `wn` applies our rename and self-update commits | ✓ |
| invite a second `wn` account with a published Add commit + Welcome | ✓ |
| remove a member; the removed member cannot read later messages | ✓ |
| SelfRemove both ways: `wn` leaves and we commit it; we hand over admin, leave, and `wn` commits it | ✓ |
| rotate the KeyPackage a Welcome consumed; `wn` invites us again with the replacement | ✓ |

The MLS layer passes the MLS working group's interop vectors for cipher suite 1 — crypto-basics, tree-math,
secret-tree, key-schedule, psk_secret, transcript-hashes, tree-validation, tree-operations, treekem,
message-protection, messages, welcome and all three passive-client files (a 200-epoch random history with 1,542
proposals, and every commit-handling vector including PSKs). The crypto layer passes the official vectors for every
primitive, run through cl-marmot's crypto bridge against the libraries above (FIPS 180, RFC 4231/5869/8439/7748/8032,
McGrew–Viega GCM, all 19 BIP-340 rows), and the NIP-44 v2 vectors run against cl-nostr.

```
./run-tests.sh                 # 52 tests, 10,947 checks
WN_BIN=/path/to/wn-dir test/interop/run-wn-interop.sh
```

## Using it

```
bin/marmot init --relay wss://relay.example --name alice   # creates and publishes an account
bin/marmot create "book club" npub1...                       # founding group with invitees
bin/marmot groups
bin/marmot send "book club" hello everyone
bin/marmot watch                                             # follow incoming traffic
```

`bin/marmot help` lists every command (`invite`, `remove`, `rename`, `promote`, `demote`, `leave`, `self-update`,
`members`, `messages`, `keypackage`, …). State lives in `$MARMOT_HOME/account.sexp` (default
`~/.local/share/cl-marmot/`); **that file holds every secret the account has — protect it.**

From Lisp, the same operations are functions on an `account` (`src/client/account.lisp`): `setup-account`, `sync`,
`create-group-with`, `invite`, `send-message`, `remove-members`, `leave-group`, ….

## Layout

```
src/util/     bytes, canonical base64, strict JSON (NIP-01 escaping), TLS/QUIC varint codec
src/crypto/   the crypto vocabulary MLS is written against, bridged to natrium / seal / secp256k1-fast
src/mls/      RFC 9420 + draft-ietf-mls-extensions-10: structures, HPKE, ratchet tree, key schedule,
              secret tree, framing, group state machine (create/commit/process/Welcome/join)
src/nostr/    Marmot-strict event decoding and tag rules over cl-nostr
src/marmot/   app components, KeyPackages (kind 30443), group validation, kind 445 envelopes, app events
src/client/   account orchestration, persistent store, CLI
test/         unit tests, MLS/NIP-44 vectors, wn interop harness
```

## Not done yet

- **Convergence** is linear: the first valid commit for an epoch wins. The spec's same-epoch race resolution,
  rollback horizon and retained-history replay (`protocol-core/convergence.md`) are not implemented.
- **Encrypted media** (MIP-04 / `encrypted-media-v2`), Blossom images, push notifications, NIP-46 remote signers,
  disbanding, and agent text streams beyond the receive-role fallback.
- **Constant time** holds where natrium and secp256k1-fast provide it; seal's AES-GCM is table-driven.
