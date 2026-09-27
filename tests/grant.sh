#!/usr/bin/env bash
# DIVE-5083: a standard (cli-scoped) seat could receive a2a messages but not send, because its
# sudo named no a2a command. This arm grades the grant `setup`/`enable` now write against the
# REAL sudo: a seat account runs `sudo -n /usr/local/bin/5dive …` and sudo itself says yes or no.
#
# Everything the arm writes is private to a mount namespace: /etc/sudoers.d, /etc/passwd,
# /usr/local/bin (a stub 5dive that runs this checkout's CLI), /var/lib/5dive (the agent
# registry) and the plugin's two trees are bound to scratch copies. The host's own sudoers,
# accounts and 5dive CLI are never read by the arm or changed. The positive control is the bug
# as shipped: before setup writes the grant, the same seat is refused.
# Needs root (re-execs under sudo -n), unshare, runuser, visudo: bash tests/grant.sh [path-to-node]
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$(readlink -f "${1:-$(command -v node)}")"
[ -x "$src" ] || { echo "grant.sh: no node at '$src'"; exit 2; }
if [ "$(id -u)" != 0 ]; then
  exec sudo -n bash "$0" "$src"
fi
for c in unshare runuser mountpoint visudo sudo getent; do command -v "$c" >/dev/null || { echo "grant.sh: needs $c"; exit 2; }; done

made_dirs=()
run="$(mktemp -d /home/a2a-grant-XXXXXX)"
cleanup() {
  rm -rf "$run"
  for d in "${made_dirs[@]}"; do rmdir "$d" 2>/dev/null; done
}
trap cleanup EXIT
for d in /etc/5dive-a2a /var/lib/5dive-a2a /var/lib/5dive; do
  [ -d "$d" ] || { mkdir -p "$d" && made_dirs+=("$d"); }
done

# A seat account that exists only inside the namespace: a free uid, in a copy of /etc/passwd.
uid=64990
while getent passwd "$uid" >/dev/null || getent group "$uid" >/dev/null; do uid=$((uid - 1)); done
seat=a2aseat
chmod 755 "$run"
mkdir -p "$run/node" "$run/lib" "$run/bin" "$run/sudoers.d" "$run/etc" "$run/var" "$run/reg"
cp "$src" "$run/node/node"
cp "$repo"/a2a/lib/*.mjs "$run/lib/"
chmod -R a+rX "$run/node" "$run/lib"
chmod 750 "$run/sudoers.d"
cp /etc/passwd "$run/passwd"
echo "agent-$seat:x:$uid:65534::/nonexistent:/bin/bash" >> "$run/passwd"
chmod 644 "$run/passwd"
# And in shadow: sudo runs PAM account checks even with NOPASSWD, and a user with no shadow line
# fails them ("account validation failure"), which would make every arm below read as refused.
cp -p /etc/shadow "$run/shadow"
echo "agent-$seat:*:19000:0:99999:7:::" >> "$run/shadow"
printf '{"agents":{"%s":{}}}\n' "$seat" > "$run/reg/agents.json"
# The stub is what `/usr/local/bin/5dive peer …` becomes here: this checkout's CLI, as the real
# dispatcher runs a plugin verb. Any other verb says so and fails, so a grant that let one
# through shows up as a stub run, never as the host's real 5dive.
cat > "$run/bin/5dive" <<STUB
#!/bin/bash
v="\${1:-}"; shift
case "\$v" in
  peer|a2a) FIVEDIVE_VERB="\$v" exec "$run/node/node" "$run/lib/cli.mjs" "\$@" ;;
  *) echo "stub-5dive: \$v \$*"; exit 3 ;;
esac
STUB
chmod 755 "$run/bin/5dive"

unshare --mount --propagation private -- bash -c '
  set -u
  run="$1" seat="agent-$2" dom=example.com
  mount --bind "$run/passwd" /etc/passwd
  mount --bind "$run/shadow" /etc/shadow
  mount --bind "$run/sudoers.d" /etc/sudoers.d
  mount --bind "$run/bin" /usr/local/bin
  mount --bind "$run/etc" /etc/5dive-a2a
  mount --bind "$run/var" /var/lib/5dive-a2a
  mount --bind "$run/reg" /var/lib/5dive
  for m in /etc/sudoers.d /usr/local/bin /etc/5dive-a2a /var/lib/5dive-a2a /var/lib/5dive; do mountpoint -q "$m" || { echo "not bound: $m"; exit 2; }; done

  pass=0 fail=0
  ok() { pass=$((pass + 1)); echo "  ok   $*"; }
  bad() { fail=$((fail + 1)); echo "  FAIL $*"; }
  # The owner is root with no sudo behind it (the arm itself came in through sudo).
  owner() { env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_COMMAND /usr/local/bin/5dive "$@"; }
  as_seat() { runuser -u "$seat" -- sudo -n /usr/local/bin/5dive "$@" 2>&1; }
  granted() { # <what the CLI must print> <args…>: sudo lets it through and the CLI runs as the seat
    local want="$1"; shift
    local o; o=$(as_seat "$@"); local rc=$?
    if [[ "$o" == *"password is required"* || "$o" == *"stub-5dive"* ]]; then bad "granted: $* -> rc $rc: $o"
    elif [[ "$o" == *$want* ]]; then ok "granted: $*"
    else bad "granted: $* -> rc $rc, wanted \"$want\": $o"; fi
  }
  refused() { # sudo itself refuses: the CLI never runs
    local o; o=$(as_seat "$@"); local rc=$?
    # Only the policy saying no counts: an account the arm built wrong is refused for every command.
    if [[ $rc -ne 0 && "$o" == *"password is required"* && "$o" != *"account validation"* ]]; then ok "refused by sudo: $*"
    else bad "refused: $* -> rc $rc: $o"; fi
  }

  echo "positive control: before setup the seat has no grant (the bug as shipped)"
  refused peer status
  refused peer send ceo hi

  echo "setup writes the grant"
  o=$(owner peer setup --no-system --domain=$dom --agents="$2" 2>&1) || { echo "$o"; bad "setup"; }
  [[ -f /etc/sudoers.d/5dive-a2a ]] && ok "/etc/sudoers.d/5dive-a2a written" || bad "no grant file: $o"
  [[ "$(stat -c %a:%U /etc/sudoers.d/5dive-a2a 2>/dev/null)" == 440:root ]] && ok "0440 root" || bad "mode/owner: $(stat -c %a:%U /etc/sudoers.d/5dive-a2a 2>&1)"
  visudo -c >/dev/null 2>&1 && ok "visudo -c on the whole policy" || bad "visudo -c: $(visudo -c 2>&1)"

  echo "the seat verbs run, as the seat"
  granted "domain $dom" peer status
  granted "\"domain\":\"$dom\"" a2a status --json
  granted "inbox empty" peer inbox
  granted "inbox empty" a2a inbox
  granted "$2" peer card
  granted "no contacts" peer contacts ls
  granted "no contacts" a2a contacts
  granted "no files being served" peer files ls
  granted "no files being served" a2a files
  granted "no file" peer files rm 00000000000000000000000000000000
  # Reaching the contact check proves sudo let it in AND the CLI saw a seat: an owner caller
  # stops earlier, at "must be called by an agent".
  granted "is not a contact" peer send ceo "hello from a standard seat"
  granted "is not a contact" a2a send ceo --reply-to=01ABC "a reply"
  granted "usage: 5dive peer card" peer card ../../../etc/shadow

  echo "the owner verbs are not in the grant"
  refused peer contacts add "x@$dom"
  refused a2a contacts add "x@$dom"
  refused peer contacts rm ceo
  refused peer files limits --max-file=1G
  refused a2a files limits --max-total=10G
  refused peer files limits
  refused peer setup
  refused a2a setup --domain=evil.$dom
  refused peer enable "$2"
  refused peer disable "$2"
  refused peer allow off
  refused peer uninstall
  refused a2a uninstall --keep-plugin
  refused peer _tick
  refused a2a rounds
  refused --json peer setup
  refused peer
  refused agent send main hi

  echo "disable takes it back"
  o=$(owner peer disable "$2" 2>&1) || bad "disable: $o"
  [[ ! -e /etc/sudoers.d/5dive-a2a ]] && ok "grant file removed with the last inbox" || bad "grant still there: $(cat /etc/sudoers.d/5dive-a2a)"
  refused peer status
  refused peer send ceo hi

  echo "enable gives it back"
  o=$(owner peer enable "$2" 2>&1) || bad "enable: $o"
  granted "inbox empty" peer inbox

  echo "grant arm: $pass pass, $fail fail"
  [ "$fail" = 0 ]
' _ "$run" "$seat"
