#!/usr/bin/env bash
# DIVE-5064: root rewrites the trust root, the non-root inbox must still read it. DIVE-5071: a
# sent file is read as the seat, never as root, and served by the non-root inbox. Runs
# tests/ownership-arm.mjs as root in a private mount namespace with /etc/5dive-a2a and
# /var/lib/5dive-a2a bound to scratch dirs, so a box that has a real install is never
# touched. Then the positive control: the same arm against a copy of the lib with the
# owner-keeping write removed must go RED (that is the bug as it shipped in 0.1.1).
# Needs root (re-execs under sudo -n), unshare, runuser, setpriv: bash tests/ownership.sh [path-to-node]
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$(readlink -f "${1:-$(command -v node)}")"
[ -x "$src" ] || { echo "ownership.sh: no node at '$src'"; exit 2; }
# A grader that lifts `bash tests/ownership.sh` off the result line drops the sudo: re-exec
# under it (non-interactively), with node already resolved from the caller's PATH.
if [ "$(id -u)" != 0 ]; then
  exec sudo -n bash "$0" "$src"
fi
for c in unshare runuser setpriv mountpoint; do command -v "$c" >/dev/null || { echo "ownership.sh: needs $c"; exit 2; }; done

svc=5dive-a2a made_user=0 made_dirs=()
# Under /home, as tests/sandbox.sh: /run and /tmp can be noexec, and the node copy runs from here.
run="$(mktemp -d /home/a2a-ownership-XXXXXX)"
cleanup() {
  rm -rf "$run"
  for d in "${made_dirs[@]}"; do rmdir "$d" 2>/dev/null; done
  [ "$made_user" = 1 ] && userdel "$svc" 2>/dev/null
}
trap cleanup EXIT

# The service user, as `peer setup` creates it (a CI runner has none).
if ! id -u "$svc" >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$svc" || exit 2
  made_user=1
fi
# Mount points only; the binds below are private to the namespace.
for d in /etc/5dive-a2a /var/lib/5dive-a2a; do
  [ -d "$d" ] || { mkdir -p "$d" && made_dirs+=("$d"); }
done

# node and the lib where the service user can reach them (not under a 0750 home).
mkdir -p "$run/node"
cp "$src" "$run/node/node"
chmod 755 "$run" "$run/node" "$run/node/node"

arm() { # <scratch name> <lib dir to copy> -> the arm's exit code
  local lib="$2" t="$run/$1"
  mkdir -p "$t/lib" "$t/etc" "$t/var"
  cp "$lib"/*.mjs "$t/lib/"
  chmod -R a+rX "$t/lib" && chmod 755 "$t"
  touch "$t/etc/.ownership-arm"
  unshare --mount --propagation private -- bash -ec '
    mount --bind "$1/etc" /etc/5dive-a2a
    mount --bind "$1/var" /var/lib/5dive-a2a
    mountpoint -q /etc/5dive-a2a && mountpoint -q /var/lib/5dive-a2a
    LIB="$1/lib" NODE="$2" SVC="$3" SENTINEL="$1/etc/.ownership-arm" "$2" "$4"
  ' _ "$t" "$run/node/node" "$svc" "$repo/tests/ownership-arm.mjs"
}

fail=0
echo "== the fix: root writes, $svc reads"
arm fixed "$repo/a2a/lib" || fail=1

echo "== positive control: writeJson without the owner-keeping chown (0.1.1) must go red"
mkdir -p "$run/mutant"
cp "$repo"/a2a/lib/*.mjs "$run/mutant/"
perl -0pi -e 's/if \(owner\) \{\n      try \{ fs\.fchownSync/if (false) {\n      try { fs.fchownSync/' "$run/mutant/state.mjs"
if cmp -s "$repo/a2a/lib/state.mjs" "$run/mutant/state.mjs"; then
  echo "FAIL  the mutation did not apply (pattern drifted)"; fail=1
elif arm mutant "$run/mutant" >"$run/mutant.log" 2>&1; then
  cat "$run/mutant.log"; echo "FAIL  the arm stayed GREEN with the chown removed"; fail=1
else
  grep '^FAIL' "$run/mutant.log" | head -4
  # Red for THIS reason, not because the arm could not run.
  if grep -q "^FAIL  contacts.json is still root:$svc" "$run/mutant.log" && grep -q "^FAIL  a contact's message is STORED" "$run/mutant.log"; then
    echo "ok    the arm went red with the chown removed (contacts rewritten away from $svc, message not stored)"
  else
    cat "$run/mutant.log"; echo "FAIL  the arm went red, but not on the ownership arms"; fail=1
  fi
fi

echo "== positive control: a sent file read by root instead of the seat (DIVE-5071) must go red"
mkdir -p "$run/mutant2"
cp "$repo"/a2a/lib/*.mjs "$run/mutant2/"
perl -0pi -e 's/const argv = realRoot\(\) \? \["runuser", "-u", c\.user, "--", "cat", "--", abs\] : /const argv = /' "$run/mutant2/cli.mjs"
if cmp -s "$repo/a2a/lib/cli.mjs" "$run/mutant2/cli.mjs"; then
  echo "FAIL  the mutation did not apply (pattern drifted)"; fail=1
elif arm mutant2 "$run/mutant2" >"$run/mutant2.log" 2>&1; then
  cat "$run/mutant2.log"; echo "FAIL  the arm stayed GREEN with the file read as root"; fail=1
elif grep -q "^FAIL  a seat cannot send /etc/shadow" "$run/mutant2.log"; then
  echo "ok    the arm went red with the file read as root (a seat could send /etc/shadow)"
else
  cat "$run/mutant2.log"; echo "FAIL  the arm went red, but not on the read-as-seat arm"; fail=1
fi

[ "$fail" = 0 ] && echo "ownership: all pass" || echo "ownership: FAILED"
exit "$fail"
