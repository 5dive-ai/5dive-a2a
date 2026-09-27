#!/usr/bin/env bash
# DIVE-5061: the inbox has no network. Runs the inbox unit's real [Service] sandbox (the
# text `peer setup` writes, from unitText + nodeDropIn) as transient units, with node
# copied under /home as on a 5dive box, and requires:
#   1. the full sandbox cannot connect to a listener on 127.0.0.1
#   2. without PrivateNetwork it still cannot (RestrictAddressFamilies holds alone)
#   3. without RestrictAddressFamilies it still cannot (PrivateNetwork holds alone)
#   4. positive control: with both removed the same probe DOES connect
#   5. without the node drop-in, node under /home does not even start (the 203/EXEC)
#   6. the real server.mjs, in the full sandbox, serves a card and takes a POST over a
#      systemd-passed unix socket
# Needs root and systemd: sudo bash tests/sandbox.sh [path-to-node]
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$(readlink -f "${1:-$(command -v node)}")"
[ "$(id -u)" = 0 ] || { echo "sandbox.sh: needs root (sudo bash tests/sandbox.sh [node])"; exit 2; }
command -v systemd-run >/dev/null || { echo "sandbox.sh: needs systemd-run"; exit 2; }
[ -x "$src" ] || { echo "sandbox.sh: no node at '$src'"; exit 2; }

fail=0 tag="a2a-arm-$$"
home="$(mktemp -d /home/a2a-sandbox-XXXXXX)"
run="/run/$tag"
node="$home/node/bin/node"
mkdir -p "$home/node/bin" "$run/lib" "$run/etc/cards" "$run/var"
cp "$src" "$node" && chmod 755 "$home/node" "$home/node/bin" "$node"
cp "$repo"/a2a/lib/*.mjs "$run/lib/"
nobody_group="$(id -gn nobody)"

listener=""
cleanup() {
  [ -n "$listener" ] && kill "$listener" 2>/dev/null
  systemctl stop "$tag.socket" "$tag.service" 2>/dev/null
  systemctl reset-failed "$tag.service" 2>/dev/null
  rm -rf "$home" "$run"
}
trap cleanup EXIT

# A host service on 127.0.0.1, as postgres is on ours.
"$src" -e 'require("net").createServer((s) => { s.on("error", () => {}); s.end("hi"); }).listen(0, "127.0.0.1", function () { require("fs").writeFileSync(process.argv[1], String(this.address().port)); });' "$run/port" &
listener=$!
for _ in $(seq 50); do [ -s "$run/port" ] && break; sleep 0.1; done
port="$(cat "$run/port")"

# The unit's [Service] lines (plus the drop-in) as -p flags, minus what the arm swaps:
# ExecStart/Restart (the arm runs its own command), User/Group (nobody: no user is
# created), and paths that only exist on an installed box become optional.
props() { # <drop: comma list of keys to remove> <with-dropin: 1|0>
  "$src" --input-type=module -e '
    const [node, drop, withDropIn] = process.argv.slice(1);
    const { unitText, nodeDropIn } = await import(process.env.A2A_CLI);
    const svc = (t) => t.split("[Service]")[1].split("\n[")[0].split("\n");
    const lines = [...svc(unitText(node)["5dive-a2a-inbox.service"]), ...(withDropIn === "1" ? svc(nodeDropIn(node)) : [])];
    const skip = new Set(["ExecStart", "Restart", "RestartSec", "User", "Group", ...drop.split(",").filter(Boolean)]);
    for (const l of lines) {
      const m = /^([A-Za-z]+)=(.*)$/.exec(l.trim());
      if (!m || skip.has(m[1])) continue;
      const v = /Paths$/.test(m[1]) && !m[2].startsWith("-") ? "-" + m[2] : m[2];
      console.log(`${m[1]}=${v}`);
    }' "$node" "$1" "$2"
}

probe() { # <drop> <with-dropin> -> CONNECTED | BLOCKED <code> | (nothing: did not start)
  local -a p=()
  while IFS= read -r l; do p+=(-p "$l"); done < <(A2A_CLI="$repo/a2a/lib/cli.mjs" props "$1" "$2")
  [ "${#p[@]}" -gt 0 ] || { echo "PROPS-EMPTY"; return; }
  timeout 30 systemd-run --quiet --wait --pipe --collect -p User=nobody -p Group="$nobody_group" "${p[@]}" -- \
    "$node" -e '
      const s = require("net").connect(Number(process.argv[1]), "127.0.0.1");
      s.on("connect", () => { console.log("CONNECTED"); process.exit(0); });
      s.on("error", (e) => { console.log("BLOCKED " + e.code); process.exit(0); });
      setTimeout(() => { console.log("BLOCKED timeout"); process.exit(0); }, 3000);' "$port" 2>&1
  echo "rc=$?"
}

arm() { # <name> <expect-regex> <got>
  set -- "$1" "$2" "$(printf '%s' "$3" | tr '\n' ' ' | sed 's/ *$//')"
  if [[ "$3" =~ $2 ]]; then printf 'ok    %-58s %s\n' "$1" "$3"
  else printf 'FAIL  %-58s got: %s\n' "$1" "${3:-<no output>}"; fail=$((fail + 1)); fi
}

echo "node under /home: $node (from $src); host listener 127.0.0.1:$port"
arm "full sandbox cannot reach 127.0.0.1:$port"                  '^BLOCKED .* rc=0$'  "$(probe "" 1)"
arm "no PrivateNetwork: RestrictAddressFamilies alone holds"      '^BLOCKED .* rc=0$'  "$(probe PrivateNetwork 1)"
arm "no RestrictAddressFamilies: PrivateNetwork alone holds"      '^BLOCKED .* rc=0$'  "$(probe RestrictAddressFamilies 1)"
arm "positive control: both removed, the probe CONNECTS"          '^CONNECTED rc=0$' "$(probe PrivateNetwork,RestrictAddressFamilies 1)"
# systemd-run --wait exits with the unit's status: 203 is EXEC, the failure teal-fox hit.
arm "no node drop-in: node under /home fails to exec (203)"      '^rc=203$' "$(probe "" 0)"

# 6. The real server, socket-activated as the socket unit does, in the full sandbox.
printf '{"agents":{"main":{"inbox":true,"did":"did:key:zArm"}}}\n' > "$run/etc/config.json"
printf '{"contacts":[]}\n' > "$run/etc/contacts.json"
printf '{"arm":"card"}\n' > "$run/etc/cards/main.json"
chmod -R a+rX "$run/etc" "$run/lib"; chown nobody "$run/var"
declare -a sp=()
while IFS= read -r l; do sp+=(-p "$l"); done < <(A2A_CLI="$repo/a2a/lib/cli.mjs" props "" 1)
systemd-run --quiet --collect --unit="$tag" --socket-property=ListenStream="$run/inbox.sock" --socket-property=SocketMode=0600 \
  -p User=nobody -p Group="$nobody_group" "${sp[@]}" -p ReadWritePaths="$run/var" \
  -E A2A_ETC="$run/etc" -E A2A_VAR="$run/var" -- "$node" "$run/lib/server.mjs" >/dev/null 2>&1
card="$(curl -s --max-time 10 --unix-socket "$run/inbox.sock" http://localhost/openagent/agents/main.json)"
arm "real server.mjs in the sandbox serves a card over the socket" '^\{"arm":"card"\}$' "$card"
post="$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' --unix-socket "$run/inbox.sock" -X POST -H 'x-forwarded-for: 192.0.2.9' --data '{}' http://localhost/openagent/inbox)"
arm "real server.mjs in the sandbox answers a POST (202)"         '^202$' "$post"
state="$(systemctl show "$tag.service" -p ActiveState --value)"
arm "the sandboxed inbox is still running"                        '^active$' "$state"

printf '\n%d failures\n' "$fail"
exit $((fail > 0))
