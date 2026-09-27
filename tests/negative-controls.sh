#!/usr/bin/env bash
# Break one load-bearing line at a time, in a scratch copy, and require the
# suite to go RED. A harness that stays green with the guard deleted is not
# testing the guard. Each mutation must change the file (a pattern that no
# longer matches is itself a failure), and must turn at least one arm red.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0 n=0

mutate() { # <name> <file> <perl-substitution>
  local name="$1" file="$2" expr="$3" tmp
  n=$((n + 1))
  tmp="$(mktemp -d)"
  cp -r "$repo/a2a" "$repo/tests" "$repo/README.md" "$tmp/"
  perl -0pi -e "$expr" "$tmp/$file"
  if cmp -s "$repo/$file" "$tmp/$file"; then
    printf 'FAIL  %-44s the mutation did not apply (pattern drifted)\n' "$name"; fail=$((fail + 1))
  elif (cd "$tmp" && node --test --test-concurrency=1 tests/*.test.mjs >/dev/null 2>&1); then
    printf 'FAIL  %-44s suite stayed GREEN with the guard removed\n' "$name"; fail=$((fail + 1))
  else
    printf 'ok    %-44s suite went red\n' "$name"
  fi
  rm -rf "$tmp"
}

mutate "stranger is not dropped before crypto"   a2a/lib/receiver.mjs 's/if \(!contact\) return drop\("drop:stranger"\);/if (!contact) {}/'
mutate "signature is not verified"                a2a/lib/receiver.mjs 's/if \(!verify\(env\)\) return drop\("drop:bad-signature"\);//'
mutate "replay is not checked"                    a2a/lib/receiver.mjs 's/if \(ctx\.store\.seen\(env\.id\)\) return drop\("drop:replay"\);//'
mutate "contact quota counted before verify"      a2a/lib/receiver.mjs 's/(  \/\/ 4\. the signature)/  if (ctx.store.verifiedCount(env.from, now - 3600 * 1000) >= 0) ctx.store.accept({ id: "x" + Math.random(), from_did: env.from, received_at: now, expires_at: now + 1 });\n$1/'
mutate "no domain separator in signed bytes"      a2a/lib/core.mjs     's/Buffer\.from\(MSG_PREFIX, "utf8"\), //'
mutate "SUDO_UID cross-check removed"             a2a/lib/cli.mjs      's/if \(byUid !== user\) throw/if (false) throw/'
mutate "a seat passes as the owner"               a2a/lib/cli.mjs      's/if \(c\.kind !== "owner"\) \{\n    throw new Refusal\(`5dive \$\{VERB\} \$\{what\}/if (false) {\n    throw new Refusal(`5dive \${VERB} \${what}/'
mutate "no debounce before delivery"              a2a/lib/cli.mjs      's/if \(!interrupt && now - items\[0\]\.rec\.received_at < DEBOUNCE_MS\)/if (false)/'
mutate "send to a non-contact"                    a2a/lib/cli.mjs      's/if \(!contact\) throw new Refusal\(`.\$\{target/if (false) throw new Refusal(`\${target/'
mutate "installed entry point never runs main()"  a2a/lib/cli.mjs      's/^if \(isEntry\(\)\) \{/if (false) {/m'
mutate "key change not caught on send"            a2a/lib/cli.mjs      's/if \(v\.ok && v\.did !== contact\.did\)/if (false)/'
mutate "inbox unit keeps its network"             a2a/lib/cli.mjs      's/^PrivateNetwork=yes\n//m'
mutate "inbox may open inet sockets"               a2a/lib/cli.mjs      's/^RestrictAddressFamilies=AF_UNIX\n//m'
mutate "node under /home is not bound"            a2a/lib/cli.mjs      's/ProtectHome=tmpfs/ProtectHome=yes/'
mutate "caddy route goes to the file's first handle" a2a/lib/cli.mjs   's/for \(let n = start \+ 1; n < end; n\+\+\)/for (let n = 0; n < lines.length; n++)/'
mutate "caddy markers found anywhere are kept"    a2a/lib/cli.mjs      's/if \(bi > t\.site\.start && ei < t\.site\.end\)/if (true)/'
mutate "caddy validate ignores EnvironmentFiles"  a2a/lib/cli.mjs      's/try \{ Object\.assign\(env, parseEnvFile\(read\(m\[1\]\)\)\); \}/try { }/'
mutate "inbox ignores the resolved allowlist"     a2a/lib/server.mjs   's/allow = al && al\.enabled \? /allow = false ? /'
mutate "unix-socket peer cannot name the client"  a2a/lib/server.mjs   's/const loop = !peer \|\| /const loop = /'
mutate "inbox reads unreadable contacts as empty" a2a/lib/server.mjs   's/const doc = readJsonStrict\(p\.contacts, /const doc = readJson(p.contacts, /'
mutate "inbox reads unreadable config as empty"   a2a/lib/server.mjs   's/const config = readJsonStrict\(p\.config, /const config = readJson(p.config, /'
mutate "unreadable trust root answers 202"        a2a/lib/server.mjs   's/if \(!ctx\) \{ res\.writeHead\(503/if (false) { res.writeHead(503/'
mutate "refresh stamp is the mtime only"          a2a/lib/server.mjs   's/return `\$\{st\.ino\}\.\$\{st\.ctimeMs\}\.\$\{st\.mtimeMs\}`;/return st.mtimeMs;/'
mutate "unreadable is logged on every message"    a2a/lib/server.mjs   's/ctx = null; allow = null; stamp = s;\n(\s*)if \(e\.message !== broken\) store\.log/ctx = null; allow = null;\n$1store.log/'
mutate "setup installs node without consent"     a2a/bin/a2a          's/    yes=0\n/    yes=1\n/'
mutate "a non-root caller installs node"          a2a/bin/a2a          's/ \]\] && is_root; then/ ]]; then/'
mutate "an old node passes the version check"     a2a/bin/a2a          's/\(\( m >= NODE_MIN \)\)/true/'
mutate "the skill is not declared"                a2a/.claude-plugin/plugin.json 's/,\n\s*"skill"//'
mutate "the verb echoes any FIVEDIVE_VERB"         a2a/lib/cli.mjs      's/process\.env\.FIVEDIVE_VERB === "a2a" \? "a2a" : "peer"/process.env.FIVEDIVE_VERB || "peer"/'
mutate "old CLIs see a2a as the verb name"         a2a/.claude-plugin/plugin.json 's/"name": "peer"/"name": "a2a"/'
mutate "the timer forgets the verb"                a2a/lib/cli.mjs      's/^Environment=FIVEDIVE_VERB=\$\{VERB\}\n//m'
mutate "bin/peer drops the typed verb"             a2a/bin/peer         's/exec /FIVEDIVE_VERB=peer exec /'
mutate "the skill drops the approval rule"        a2a/skills/message-agents/SKILL.md 's/never approves/can approve/'

printf '\n%d mutations, %d red as required, %d failures\n' "$n" "$((n - fail))" "$fail"
exit $((fail > 0))
