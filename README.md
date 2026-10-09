# cl-marmot

A [Marmot](https://github.com/marmot-protocol/marmot) client in portable Common Lisp: end-to-end encrypted group
messaging with MLS ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)) over Nostr relays, the protocol
[White Noise](https://github.com/marmot-protocol/whitenoise-linux) speaks.

Everything is written from the specifications in plain ANSI Common Lisp: the MLS state machine, HPKE, AES-GCM,
ChaCha20-Poly1305, X25519, Ed25519, secp256k1/BIP-340, NIP-44, NIP-59, the websocket client and the JSON codec.
There are no foreign libraries and no Quicklisp dependencies. The only implementation-specific code is a socket and
entropy shim (`src/util/platform.lisp`) that goes through the `SB-BSD-SOCKETS` interface, which SBCL provides natively
and Modus provides as a compatibility surface.

## Status

It interoperates with mdk's `wn`, the engine whitenoise-linux links through `marmot-c`
(`test/interop/run-wn-interop.sh`, **21 of 21** steps, fresh relay and accounts each run):

| | |
|---|---|
| join a group created by `wn` from its Welcome | ✓ |
| messages in both directions (kind 9 app events in MLS PrivateMessages, kind 445 envelopes) | ✓ |
| apply `wn`'s commits: rename (AppDataUpdate), remove us | ✓ |
| create a group `wn` joins; `wn` applies our rename and self-update commits | ✓ |
| invite a second `wn` account with a published Add commit + Welcome | ✓ |
| remove a member; the removed member cannot read later messages | ✓ |
| SelfRemove both ways: `wn` leaves and we commit it; we hand over admin, leave, and `wn` commits it | ✓ |

The MLS layer passes the MLS working group's interop vectors for cipher suite 1 — crypto-basics, tree-math,
secret-tree, key-schedule, psk_secret, transcript-hashes, tree-validation, tree-operations, treekem,
message-protection, messages, welcome and all three passive-client files (a 200-epoch random history with 1,542
proposals, and every commit-handling vector including PSKs). The crypto layer passes the official vectors for every
primitive (FIPS 180, RFC 4231/5869/8439/7748/8032, McGrew–Viega GCM, all 19 BIP-340 rows, all NIP-44 v2 vectors).

```
./run-tests.sh                 # 53 tests, 10,950 checks
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
src/util/     bytes, base64/bech32, JSON (NIP-01 escaping), TLS/QUIC varint codec, platform shim
src/crypto/   SHA-1/2, HMAC/HKDF, ChaCha20-Poly1305, AES-GCM, X25519, Ed25519, secp256k1/BIP-340
src/mls/      RFC 9420 + draft-ietf-mls-extensions-10: structures, HPKE, ratchet tree, key schedule,
              secret tree, framing, group state machine (create/commit/process/Welcome/join)
src/nostr/    events, NIP-44 v2, NIP-59, RFC 6455 websocket client, relay pool
src/marmot/   app components, KeyPackages (kind 30443), group validation, kind 445 envelopes, app events
src/client/   account orchestration, persistent store, CLI
test/         unit tests, MLS/NIP-44 vectors, wn interop harness
```

## Not done yet

- **TLS.** Only `ws://` relays work out of the box; `wss://` needs a TLS 1.3 client, which is not written yet.
  `*tls-connect-function*` is the hook for one.
- **Convergence** is linear: the first valid commit for an epoch wins. The spec's same-epoch race resolution,
  rollback horizon and retained-history replay (`protocol-core/convergence.md`) are not implemented.
- **Encrypted media** (MIP-04 / `encrypted-media-v2`), Blossom images, push notifications, NIP-46 remote signers,
  message retention expiry tags, disbanding, and agent text streams beyond the receive-role fallback.
- **Constant time.** The bignum elliptic-curve code and table-driven AES are not constant time.
- Fresh-KeyPackage rotation after a Welcome consumes a single-use package (we publish last-resort packages, which
  remain valid).
