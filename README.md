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
test/fetch-vectors.sh          # the MLS WG and NIP-44 vectors, pinned and checksummed
./run-tests.sh                 # 59 tests, 10,984 checks
WN_BIN=/path/to/wn-dir test/interop/run-wn-interop.sh
```

The external vectors are fetched rather than vendored (their repositories declare no licence); a missing vector
file fails the suite rather than skipping it.

## Installing

cl-marmot runs on SBCL. It needs five [modus-lisp](https://github.com/modus-lisp) libraries, checked out next to it
(or anywhere, with `MODUS_LISP` pointing at their parent directory), and [Quicklisp](https://www.quicklisp.org/) for
`bordeaux-threads` and `cl-base64`:

```sh
mkdir modus-lisp && cd modus-lisp
for repo in cl-marmot natrium secp256k1-fast seal cl-nostr json-simple; do
  git clone https://github.com/modus-lisp/$repo.git
done
cd cl-marmot
test/fetch-vectors.sh && ./run-tests.sh      # optional: the test suite
bin/marmot help
```

From Lisp: `(load "load-deps.lisp")` (it loads Quicklisp and registers the siblings), then
`(ql:quickload :cl-marmot)`.

## Lisp API

The public API is the `MARMOT` package (`src/api.lisp`):

```lisp
(load "load-deps.lisp") (ql:quickload :cl-marmot)

(marmot:with-account (c)                       ; $MARMOT_HOME or ~/.local/share/cl-marmot/
  (marmot:add-handler c (lambda (e)
                          (when (eq (marmot:event-type e) :message)
                            (let ((m (marmot:event-message e)))
                              (format t "~A: ~A~%" (marmot:message-sender m) (marmot:message-content m))))))
  (let ((chat (marmot:create-chat c '("ynniv@ynniv.com"))))   ; npub, hex or NIP-05; empty name = 1:1
    (marmot:send c chat "hello"))
  (marmot:start c)                             ; background sync, and serve the CLI socket
  (sleep 600))
```

| | |
|---|---|
| accounts | `create-account` `open-account` `close-account` `with-account` `npub` `pubkey` `relays` `publish-key-package` |
| chats | `chats` `find-chat` `chat-id` `chat-name` `chat-description` `chat-members` `chat-admins` `chat-epoch` `chat-active-p` `chat-leaving-p` `chat-messages` |
| messages | `message-id` `message-chat-id` `message-sender` `message-kind` `message-content` `message-tags` `message-created-at` `message-epoch` `message-own-p` `message-edited-p` `message-reply-to` `message-reactions` `message-invalidated-p` |
| people | `profile` `display-name` |
| actions | `create-chat` `send` `invite` `remove-members` `rename` `promote` `demote` `leave` `self-update` |
| events | `sync` `start` `stop` `running-p` `add-handler` `remove-handler`; `event-type`, `event-chat`, `event-message`, `event-account`, `event-epoch`, `event-name`, `event-reason`, `event-commit`, `event-message-id`, `event-target-id`, `event-invitees` |

`chat-messages` returns kind 9 chat messages with edits (kind 1009, by the original author) and reactions (kind 7)
applied; push-notification bookkeeping and group system rows are not messages. Event types are `:message` `:edit`
`:reaction` `:app-event` `:joined` `:member-added` `:member-removed` `:renamed` `:epoch` `:removed`
`:pending-superseded` `:commit-invalidated` `:message-invalidated` `:rejected` (see the `event` docstring). When two
members commit at once, every member converges on the same branch (`protocol-core/convergence.md`); if a change you
were shown loses, `:commit-invalidated` and `:message-invalidated` say so.

An open client owns its account: a lock file keeps other processes out (two writers would reuse MLS message keys),
and a recursive lock makes the API safe to call from the application's threads while the background thread syncs.
Every change is saved before the call returns. Handlers run outside the lock, so they may call back into the API.

## Command line

```
bin/marmot init --relay wss://relay.damus.io --relay wss://nos.lol --name alice
bin/marmot create "" ynniv@ynniv.com                   # a one-to-one chat
bin/marmot send 1e81d2b5 hello                          # CHAT: id, id prefix or name
bin/marmot daemon &                                     # hold the account, sync in the background
bin/marmot messages 1e81d2b5                            # ...forwarded to the daemon
```

Whatever process holds the account — `marmot daemon`, `marmot watch` (the same, printing what arrives), or an
application that called `marmot:start` — listens on `$MARMOT_HOME/marmot.sock` (owner-only). Other `marmot`
commands find it and run inside that process instead of failing on the lock. `bin/marmot help` lists every command.
The account file holds every secret the account has and is written owner-only.

## Security

cl-marmot is new and **has not been audited**. Its MLS, Marmot and Nostr code is checked against the published test
vectors and against mdk; that is evidence of interoperability, not of security. Secret-key operations use natrium
and secp256k1-fast, which are written for constant time; seal's AES-GCM (used for MLS message encryption) is
table-driven and is not. The account file and message log hold every key and message the account has, are written
owner-only, and are not encrypted at rest.

## Layout

```
src/util/     bytes, canonical base64, strict JSON (NIP-01 escaping), TLS/QUIC varint codec
src/crypto/   the crypto vocabulary MLS is written against, bridged to natrium / seal / secp256k1-fast
src/mls/      RFC 9420 + draft-ietf-mls-extensions-10: structures, HPKE, ratchet tree, key schedule,
              secret tree, framing, group state machine (create/commit/process/Welcome/join)
src/nostr/    Marmot-strict event decoding and tag rules over cl-nostr
src/marmot/   app components, KeyPackages (kind 30443), group validation, kind 445 envelopes, app events
src/client/   account orchestration, persistent store, account lock
src/api.lisp  the public MARMOT package
src/cli.lisp  the `marmot` command line and its socket
test/         unit tests, MLS/NIP-44 vectors, wn interop harness
```

## Not done yet

- **Convergence** follows the spec's branch selection within the rollback horizon, but not its millisecond
  collection windows (each sync batch plays that role), retained-history replay beyond the horizon, or disband
  terminalization.
- **Encrypted media** (MIP-04 / `encrypted-media-v2`), Blossom images, push notifications, NIP-46 remote signers,
  disbanding, and agent text streams beyond the receive-role fallback.
- **Modus**: cl-marmot loads on Modus, but runs far slower there than on SBCL; SBCL is the supported platform.
