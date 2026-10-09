#!/bin/sh
# run-wn-interop.sh — cl-marmot against mdk's `wn`, the engine whitenoise-linux
# embeds (whitenoise-linux links mdk's marmot-c; `wn` is the same runtime with
# a CLI).  Everything runs against a throwaway in-memory relay (`nak serve`)
# on 127.0.0.1 with fresh homes, and every step is asserted.
#
#   WN_BIN=/path/to/dir-with-wn-and-wnd  test/interop/run-wn-interop.sh
#
# Build wn at the mdk commit whitenoise-linux pins (its DEPS_PIN):
#   cargo build --release --locked -p wn-cli --bins
set -u
here="$(cd "$(dirname "$0")/../.." && pwd)"
: "${WN_BIN:?set WN_BIN to the directory holding wn and wnd}"
PATH="$WN_BIN:$PATH"
command -v nak >/dev/null || { echo "nak not found"; exit 2; }

work="$(mktemp -d "${TMPDIR:-/tmp}/cl-marmot-interop.XXXXXX")"
port=$((20000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 20000))
relay="ws://127.0.0.1:$port"
export WN_HOME="$work/wn" WN_SECRET_STORE=file WN_ALLOW_LOOPBACK_RELAYS=1
unset WN_SOCKET
export MARMOT_HOME="$work/marmot"
marmot="$here/bin/marmot"
pass=0; fail=0

cleanup() {
  wn daemon stop >/dev/null 2>&1
  [ -n "${relay_pid:-}" ] && kill "$relay_pid" 2>/dev/null
  [ "${KEEP:-0}" = 1 ] && echo "kept $work" || rm -rf "$work"
}
trap cleanup EXIT

check() {  # check NAME COMMAND-PRODUCING-OUTPUT PATTERN
  name="$1"; out="$2"; pat="$3"
  if printf '%s' "$out" | grep -q -- "$pat"; then
    pass=$((pass + 1)); echo "ok   $name"
  else
    fail=$((fail + 1)); echo "FAIL $name"; printf '%s\n' "$out" | sed 's/^/     | /' | head -20
  fi
}

nak serve --hostname 127.0.0.1 --port "$port" -q >"$work/relay.log" 2>&1 &
relay_pid=$!
sleep 1
wn daemon start --discovery-relays "$relay" --default-account-relays "$relay" >/dev/null 2>&1

alice=$(wn --json create-identity | sed -n 's/.*"npub":"\(npub1[0-9a-z]*\)".*/\1/p' | head -1)
bob=$(wn --json create-identity | sed -n 's/.*"npub":"\(npub1[0-9a-z]*\)".*/\1/p' | head -1)
carol=$("$marmot" init --relay "$relay" --name carol)
echo "relay $relay  alice(wn) $alice  bob(wn) $bob  carol(cl-marmot) $carol"
settle() { sleep "${1:-3}"; }

# --- A: wn creates the group, cl-marmot joins ------------------------------
out=$(wn --json --account "$alice" groups create "from wn" "$carol" 2>&1)
gA=$(printf '%s' "$out" | sed -n 's/.*"group_id":"\([0-9a-f]*\)".*/\1/p')
check "A wn creates a group with carol" "$out" '"ok":true'
settle
check "A carol joins from wn's Welcome" "$("$marmot" groups)" "$gA"
"$marmot" send "$gA" "hello from lisp" >/dev/null
settle
check "A wn decrypts carol's message" "$(wn --account "$alice" messages list "$gA")" "hello from lisp"
wn --account "$alice" messages send "$gA" "hello from wn" >/dev/null 2>&1
settle
check "A carol decrypts wn's message" "$("$marmot" messages "$gA")" "hello from wn"
wn --account "$alice" groups rename "$gA" "renamed by wn" >/dev/null 2>&1
settle
check "A carol applies wn's rename commit" "$("$marmot" groups)" "renamed by wn"
wn --account "$alice" messages send "$gA" "after the rename" >/dev/null 2>&1
settle
check "A carol decrypts in the new epoch" "$("$marmot" messages "$gA")" "after the rename"
"$marmot" self-update "$gA" >/dev/null
"$marmot" send "$gA" "after my self-update" >/dev/null
settle
check "A wn applies carol's self-update" "$(wn --account "$alice" messages list "$gA")" "after my self-update"

# --- B: cl-marmot creates the group, wn joins ------------------------------
gB=$("$marmot" create "from lisp" "$alice" | sed -n 's/^created //p')
settle 5
check "B wn sees cl-marmot's Welcome" "$(wn --account "$alice" groups invites)" "$gB"
wn --account "$alice" groups accept "$gB" >/dev/null 2>&1
wn --account "$alice" messages send "$gB" "wn in a lisp group" >/dev/null 2>&1
settle
check "B carol decrypts wn's message" "$("$marmot" messages "$gB")" "wn in a lisp group"
"$marmot" send "$gB" "lisp admin here" >/dev/null
settle
check "B wn decrypts carol's message" "$(wn --account "$alice" messages list "$gB")" "lisp admin here"
"$marmot" rename "$gB" "lisp renamed it" >/dev/null
settle
check "B wn applies carol's rename commit" "$(wn --account "$alice" groups show "$gB")" "lisp renamed it"
"$marmot" invite "$gB" "$bob" >/dev/null
settle 5
wn --account "$bob" groups accept "$gB" >/dev/null 2>&1
wn --account "$bob" messages send "$gB" "bob via lisp invite" >/dev/null 2>&1
settle
check "B bob joins via a published Add + Welcome" "$("$marmot" messages "$gB")" "bob via lisp invite"
check "B alice applies the Add commit" "$(wn --account "$alice" messages list "$gB")" "bob via lisp invite"
"$marmot" remove "$gB" "$bob" >/dev/null
"$marmot" send "$gB" "post-removal secret" >/dev/null
settle
check "B alice applies the Remove commit" "$(wn --account "$alice" messages list "$gB")" "post-removal secret"
out=$(wn --account "$bob" messages list "$gB" 2>&1)
if printf '%s' "$out" | grep -q "post-removal secret"; then
  fail=$((fail + 1)); echo "FAIL B removed bob cannot read later messages"
else
  pass=$((pass + 1)); echo "ok   B removed bob cannot read later messages"
fi

# --- C: a wn member leaves a cl-marmot group (SelfRemove committed by us) --
wn --account "$alice" groups leave "$gB" >/dev/null 2>&1
settle
"$marmot" sync >/dev/null
settle
check "C carol commits wn's SelfRemove" "$("$marmot" members "$gB")" "(you)"
out=$("$marmot" members "$gB")
if printf '%s' "$out" | grep -q "$alice"; then
  fail=$((fail + 1)); echo "FAIL C alice is gone from carol's group"; printf '%s\n' "$out" | sed 's/^/     | /'
else
  pass=$((pass + 1)); echo "ok   C alice is gone from carol's group"
fi

# --- D: cl-marmot hands over admin and leaves; wn commits our SelfRemove --
gD=$("$marmot" create "handover" "$alice" | sed -n 's/^created //p')
settle 5
wn --account "$alice" groups accept "$gD" >/dev/null 2>&1
settle
"$marmot" promote "$gD" "$alice" >/dev/null
settle
check "D wn sees itself promoted" "$(wn --account "$alice" groups admins "$gD")" "$alice"
"$marmot" leave "$gD" >/dev/null
settle 8
wn --account "$alice" groups members "$gD" >/dev/null 2>&1
settle 4
check "D carol is removed after wn commits her SelfRemove" "$("$marmot" groups | grep "$gD")" "removed"
out=$(wn --account "$alice" groups members "$gD" 2>&1)
if printf '%s' "$out" | grep -q "$carol"; then
  fail=$((fail + 1)); echo "FAIL D wn no longer lists carol"; printf '%s\n' "$out" | sed 's/^/     | /'
else
  pass=$((pass + 1)); echo "ok   D wn no longer lists carol"
fi

# --- E: a wn admin removes cl-marmot ---------------------------------------
wn --account "$alice" groups remove-members "$gA" "$carol" >/dev/null 2>&1
settle
check "E carol realizes wn's removal" "$("$marmot" groups | grep "$gA")" "removed"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
