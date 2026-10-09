#!/bin/sh
# run-wn-media.sh — encrypted media (encrypted-media-v2) between cl-marmot and
# mdk's `wn`, against a throwaway local relay that is also a Blossom server
# (`nak serve --blossom`).  Nothing leaves 127.0.0.1.
#
#   WN_BIN=/path/to/dir-with-wn-and-wnd  test/interop/run-wn-media.sh
set -u
here="$(cd "$(dirname "$0")/../.." && pwd)"
: "${WN_BIN:?set WN_BIN to the directory holding wn and wnd}"
PATH="$WN_BIN:$PATH"
command -v nak >/dev/null || { echo "nak not found"; exit 2; }

work="$(mktemp -d "${TMPDIR:-/tmp}/cl-marmot-media.XXXXXX")"
port=$((20000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 20000))
relay="ws://127.0.0.1:$port"
blossom="http://127.0.0.1:$port/"
export WN_HOME="$work/wn" WN_SECRET_STORE=file WN_ALLOW_LOOPBACK_RELAYS=1 WN_ALLOW_LOOPBACK_BLOB_ENDPOINTS=1
export MARMOT_HOME="$work/marmot" MARMOT_ALLOW_LOOPBACK_MEDIA=1
unset WN_SOCKET
marmot="$here/bin/marmot"
pass=0; fail=0
cleanup() {
  wn daemon stop >/dev/null 2>&1
  [ -n "${relay_pid:-}" ] && kill "$relay_pid" 2>/dev/null
  [ "${KEEP:-0}" = 1 ] && echo "kept $work" || rm -rf "$work"
}
trap cleanup EXIT
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/     | /' | head -20; }
check() { if printf '%s' "$2" | grep -q -- "$3"; then ok "$1"; else bad "$1" "$2"; fi; }
same() { if cmp -s "$2" "$3"; then ok "$1"; else bad "$1" "$(ls -l "$2" "$3" 2>&1)"; fi; }
wn() { timeout "${WN_TIMEOUT:-90}" "$WN_BIN/wn" "$@"; }
settle() { sleep "${1:-3}"; }

nak serve --hostname 127.0.0.1 --port "$port" --blossom -q >"$work/relay.log" 2>&1 &
relay_pid=$!
sleep 1
wn daemon start --discovery-relays "$relay" --default-account-relays "$relay" >/dev/null 2>&1
alice=$(wn --json create-identity | sed -n 's/.*"npub":"\(npub1[0-9a-z]*\)".*/\1/p' | head -1)
carol=$("$marmot" init --relay "$relay" --name carol)
echo "relay+blossom 127.0.0.1:$port  alice(wn) $alice  carol(cl-marmot) $carol"

# test files: binary, with a name that has a space
head -c 70000 /dev/urandom > "$work/photo one.png"
head -c 3000 /dev/urandom > "$work/note.pdf"

# --- wn's group, pointed at the local Blossom server --------------------------
out=$(wn --json --account "$alice" groups create "media" "$carol" 2>&1)
g=$(printf '%s' "$out" | sed -n 's/.*"group_id":"\([0-9a-f]*\)".*/\1/p')
check "wn creates a group with carol" "$out" '"ok":true'
out=$(wn --account "$alice" media set-endpoints "$g" "$blossom" 2>&1)
check "alice points the group's media policy at the local server" "$out" "."
settle
check "carol joins" "$("$marmot" chats)" "$g"

# --- cl-marmot -> wn ----------------------------------------------------------
out=$("$marmot" send-file "$g" "$work/photo one.png" --caption "a photo from lisp" 2>&1)
check "carol uploads and sends a file" "$out" "photo one.png  image/png  http://127.0.0.1:$port/"
settle
out=$(wn --account "$alice" messages list "$g" --limit 10 2>&1)
check "alice sees carol's caption" "$out" "a photo from lisp"
list=$(wn --json --account "$alice" media list "$g" 2>&1)
check "alice's media list has carol's file" "$list" "photo one.png"
hash=$(printf '%s' "$list" | tr ',' '\n' | sed -n 's/.*"\(plaintext_sha256\|file_hash\)":"\([0-9a-f]\{64\}\)".*/\2/p' | head -1)
mkdir -p "$work/alice-dl"
out=$(wn --account "$alice" media download "$g" "$hash" --output "$work/alice-dl/" 2>&1)
check "alice downloads and decrypts it" "$out" "."
same "alice's copy is byte-identical" "$work/photo one.png" "$work/alice-dl/photo one.png"

# --- wn -> cl-marmot ----------------------------------------------------------
out=$(wn --account "$alice" media upload "$g" "$work/note.pdf" --send --message "a pdf from wn" 2>&1)
check "alice uploads and sends a file" "$out" "."
settle
out=$("$marmot" messages "$g" 10)
check "carol sees alice's caption" "$out" "a pdf from wn"
check "carol sees the attachment" "$out" "note.pdf  application/pdf"
fetch=$(printf '%s' "$out" | grep "note.pdf" | sed -n 's/.*(fetch \([0-9a-f]*\) \([0-9]*\)).*/\1 \2/p' | head -1)
mkdir -p "$work/carol-dl"
out=$(cd "$work/carol-dl" && "$marmot" fetch "$g" $fetch 2>&1)
check "carol fetches and decrypts it" "$out" "saved"
same "carol's copy is byte-identical" "$work/note.pdf" "$work/carol-dl/note.pdf"

# --- after an epoch change both old files still open --------------------------
"$marmot" self-update "$g" >/dev/null
settle
wn --account "$alice" messages send "$g" "new epoch" >/dev/null 2>&1
settle
rm -f "$work/carol-dl/note.pdf"
out=$(cd "$work/carol-dl" && "$marmot" fetch "$g" $fetch 2>&1)
same "carol still opens the epoch-1 file after a commit" "$work/note.pdf" "$work/carol-dl/note.pdf"
rm -rf "$work/alice-dl"; mkdir -p "$work/alice-dl"
wn --account "$alice" media download "$g" "$hash" --output "$work/alice-dl/" >/dev/null 2>&1
same "so does alice" "$work/photo one.png" "$work/alice-dl/photo one.png"

# --- a group cl-marmot creates carries a policy wn accepts --------------------
out=$("$marmot" create "lisp media" "$alice")
g2=$(printf '%s' "$out" | sed -n 's/created \([0-9a-f]*\)/\1/p')
settle
wn --account "$alice" groups accept "$g2" >/dev/null 2>&1
out=$(wn --account "$alice" groups show "$g2" 2>&1)
check "wn accepts carol's group (with its 0x800b media policy)" "$out" "lisp media"
out=$("$marmot" send-file "$g2" "$work/note.pdf" --server "$blossom" --caption "explicit server" 2>&1)
check "carol sends to an explicit server" "$out" "note.pdf"
settle
list=$(wn --json --account "$alice" media list "$g2" 2>&1)
check "alice sees it in carol's group" "$list" "note.pdf"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
