#!/bin/sh
# fetch-vectors.sh — download the external test vectors at pinned commits.
#
# They are not vendored: neither source repository declares a licence, so this
# repository points at them instead of copying them.  Every file is checked
# against its SHA-256 before the suite will use it.
set -eu
dir="$(cd "$(dirname "$0")" && pwd)/vectors"
mkdir -p "$dir"
MLS=2034fe72e0c805a683ba76165660c834f2a8142a       # github.com/mlswg/mls-implementations
NIP44=1f8dba1707d065b39329b75012a13a6d1d8124f5     # github.com/paulmillr/nip44

fetch() {  # fetch URL FILE SHA256
  if [ -f "$dir/$2" ] && echo "$3  $dir/$2" | sha256sum -c --quiet - 2>/dev/null; then return; fi
  curl -fsSL "$1" -o "$dir/$2.tmp"
  echo "$3  $dir/$2.tmp" | sha256sum -c --quiet - || { rm -f "$dir/$2.tmp"; echo "checksum mismatch: $2" >&2; exit 1; }
  mv "$dir/$2.tmp" "$dir/$2"
  echo "fetched $2"
}

mls() { fetch "https://raw.githubusercontent.com/mlswg/mls-implementations/$MLS/test-vectors/$1" "$1" "$2"; }
mls crypto-basics.json                  17cfcf89af9f51d0f2aa7af77f6f9ec99376a039214b6d42a6f11646b83e8c29
mls tree-math.json                      27f04891f56106593b74b674445f01b845e173953770c084deb2f8cf5592e2fc
mls secret-tree.json                    08f92e6272452e2c832e32d38e16cf0c4aa28967e47d3842c60bc354c6b67a94
mls key-schedule.json                   05aa9a68bd2538ace72d8c53375984cc728ef62220ebf314df675708546d97a7
mls psk_secret.json                     2b534969dba0b65a04b7d790496af5c0ccdb472b3fc4ca25c8c82df3e8523784
mls transcript-hashes.json              58046b58fbd98519b4e60953a105f550e4b427e2b140ea67dedcb751260eecb8
mls tree-validation.json                b66a432d93b520623f0640835ed43b9dfc95e116b8be081d81581d7c11e67a37
mls tree-operations.json                9a25f8720714d1256ba2dad8d83a660ba0bae0d33ed15c682b9d74a5d67aad0a
mls treekem.json                        d8bbdf78394797f21db7476fd286af6830ebcb18d2e3b2c839fecd4eb11056f8
mls message-protection.json             f7c1ae62ce63c3003e526d539c99f2b1444f65ee0a487d3a5667d46867526c45
mls messages.json                       b194abe1561995223482dbad51c180146920dc2f637e74d01e07a388308791fb
mls welcome.json                        06be9d5c99817ef2545e4b15b8e73fd9b604685a8e55b59ca168eda98e236502
mls passive-client-welcome.json         92ebb04b67b1aca4290965ae363650921842ceebe275bd79a2733414078d849c
mls passive-client-handling-commit.json b24949fdf857bf79d511f57504a8bdc7ce3247eb199684745e439c11b1a1da21
mls passive-client-random.json          0095d863e9d316872e237fc708debcd20ba2687ee905a3e831f97dd3e578d3c1
fetch "https://raw.githubusercontent.com/paulmillr/nip44/$NIP44/nip44.vectors.json" nip44.vectors.json \
      269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040
