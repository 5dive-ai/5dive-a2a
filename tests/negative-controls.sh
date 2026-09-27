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
  cp -r "$repo/a2a" "$repo/tests" "$tmp/"
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
mutate "a seat passes as the owner"               a2a/lib/cli.mjs      's/if \(c\.kind !== "owner"\) \{\n    throw new Refusal\(`5dive peer \$\{what\}/if (false) {\n    throw new Refusal(`5dive peer \${what}/'
mutate "no debounce before delivery"              a2a/lib/cli.mjs      's/if \(!interrupt && now - items\[0\]\.rec\.received_at < DEBOUNCE_MS\)/if (false)/'
mutate "send to a non-contact"                    a2a/lib/cli.mjs      's/if \(!contact\) throw new Refusal\(`.\$\{target/if (false) throw new Refusal(`\${target/'
mutate "installed entry point never runs main()"  a2a/lib/cli.mjs      's/^if \(isEntry\(\)\) \{/if (false) {/m'
mutate "key change not caught on send"            a2a/lib/cli.mjs      's/if \(v\.ok && v\.did !== contact\.did\)/if (false)/'

printf '\n%d mutations, %d red as required, %d failures\n' "$n" "$((n - fail))" "$fail"
exit $((fail > 0))
