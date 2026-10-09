#!/bin/sh
# run-wn-scale.sh — cl-marmot in a larger group of mdk `wn` clients.
#
#   WN_BIN=/path/to/wn-dir test/interop/run-wn-scale.sh [MEMBERS]
#
# MEMBERS wn accounts (default 30) and one cl-marmot account in one group on a
# throwaway local relay: the cl-marmot member joins from wn's Welcome, wn
# members talk, the admin removes members and renames, two wn admins rename at
# the same moment (a real commit race), and everyone must end up agreeing.
set -u
here="$(cd "$(dirname "$0")/../.." && pwd)"
: "${WN_BIN:?set WN_BIN to the directory holding wn and wnd}"
PATH="$WN_BIN:$PATH"
N="${1:-30}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cl-marmot-scale.XXXXXX")"
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
ok()   { pass=$((pass + 1)); echo "ok   $1"; }
bad()  { fail=$((fail + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/     | /' | head -15; }
check() { if printf '%s' "$2" | grep -q -- "$3"; then ok "$1"; else bad "$1" "$2"; fi; }
npub_of() { sed -n 's/.*"npub":"\(npub1[0-9a-z]*\)".*/\1/p' | head -1; }
# every wn call is bounded: a hang must show up as a failure, not as a stuck run
wn() { timeout "${WN_TIMEOUT:-90}" "$WN_BIN/wn" "$@"; }
step() { echo "--- $(date +%T) $*"; }

nak serve --hostname 127.0.0.1 --port "$port" -q >"$work/relay.log" 2>&1 &
relay_pid=$!
sleep 1
wn daemon start --discovery-relays "$relay" --default-account-relays "$relay" >/dev/null 2>&1

t0=$(date +%s)
i=0; : > "$work/members"
while [ "$i" -lt "$N" ]; do
  wn --json create-identity 2>/dev/null | npub_of >> "$work/members"
  i=$((i + 1))
done
alice=$(sed -n 1p "$work/members"); bob=$(sed -n 2p "$work/members")
carol=$("$marmot" init --relay "$relay" --name carol)
echo "$N wn accounts in $(( $(date +%s) - t0 ))s; carol(cl-marmot) $carol"

step "group creation"
# --- one group: alice (admin) + every other wn account + carol --------------
others=$(sed -n "2,${N}p" "$work/members" | tr '\n' ' ')
t0=$(date +%s)
out=$(wn --json --account "$alice" groups create "scale test" $others "$carol" 2>&1)
g=$(printf '%s' "$out" | sed -n 's/.*"group_id":"\([0-9a-f]*\)".*/\1/p')
echo "wn created the $((N + 1))-member group in $(( $(date +%s) - t0 ))s"
check "group created" "$out" '"ok":true'
sleep 3
t0=$(date +%s); out=$("$marmot" chats)
echo "carol's first sync (join): $(( $(date +%s) - t0 ))s"
check "carol joins the $((N + 1))-member group" "$out" "$((N + 1)) members"

step "members talk"
# --- several wn members accept and talk -------------------------------------
for k in 2 3 4 5 6; do
  m=$(sed -n "${k}p" "$work/members")
  wn --account "$m" groups accept "$g" >/dev/null 2>&1
  wn --account "$m" messages send "$g" "hello from member $k" >/dev/null 2>&1
done
sleep 3
out=$("$marmot" messages "$g" 50)
n=$(printf '%s' "$out" | grep -c "hello from member")
[ "$n" = 5 ] && ok "carol decrypts messages from 5 wn members" || bad "carol decrypts messages from 5 wn members ($n)" "$out"
"$marmot" send "$g" "carol in a big group" >/dev/null
sleep 3
check "the admin decrypts carol" "$(wn --account "$alice" messages list "$g" --limit 50)" "carol in a big group"
check "another wn member decrypts carol" "$(wn --account "$(sed -n 4p "$work/members")" messages list "$g" --limit 50)" "carol in a big group"

step "removals and rename"
# --- the admin removes three members and renames ----------------------------
victims=$(sed -n "$((N - 2)),${N}p" "$work/members" | tr '\n' ' ')
wn --account "$alice" groups remove-members "$g" $victims >/dev/null 2>&1
wn --account "$alice" groups rename "$g" "scale test renamed" >/dev/null 2>&1
sleep 3
out=$("$marmot" chats)
check "carol applies the removals" "$out" "$((N - 2)) members"
check "carol applies the rename" "$out" "scale test renamed"

# --- a real race: two admins rename at the same moment ----------------------
step "promote bob"
out=$(wn --account "$alice" groups promote "$g" "$bob" 2>&1); echo "    promote: $(printf '%s' "$out" | tail -1)"
sleep 3
step "concurrent renames"
wn --account "$bob" groups accept "$g" >/dev/null 2>&1
wn --account "$alice" groups rename "$g" "alice wins?" > "$work/ra" 2>&1 & pa=$!
wn --account "$bob" groups rename "$g" "bob wins?" > "$work/rb" 2>&1 & pb=$!
wait "$pa" "$pb"   # not a bare `wait`: the relay is a background job too
echo "    alice: $(tail -1 "$work/ra")"; echo "    bob:   $(tail -1 "$work/rb")"
sleep 6
"$marmot" sync >/dev/null
na=$(wn --account "$alice" groups show "$g" 2>&1 | sed -n 's/.* name=\(.*\) endpoint.*/\1/p')
nb=$(wn --account "$bob" groups show "$g" 2>&1 | sed -n 's/.* name=\(.*\) endpoint.*/\1/p')
nc=$("$marmot" chats | grep "$g" | sed 's/.*active  *//')
echo "after the race: alice sees '$na', bob sees '$nb', carol sees '$nc'"
if [ -n "$nc" ] && [ "$na" = "$nc" ] && [ "$nb" = "$nc" ]; then ok "all three agree after the race"; else bad "all three agree after the race"; fi
"$marmot" send "$g" "after the race" >/dev/null
sleep 3
check "the group still works for everyone" "$(wn --account "$bob" messages list "$g" --limit 50)" "after the race"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
