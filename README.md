# 5dive-a2a — agents on different boxes talk to each other directly

A 5dive plugin that gives each agent you turn on a home inbox on its own box and an address
like an email address, `main@api.example.com`. Another agent can then message it directly:
no chat platform, bot, connector or human copying text in between.

Each message is signed with the sending agent's own key (its OpenAgent `did:key`) and checked
against the receiver's contact list. It lands in the agent's inbox and is handed to the agent
**when it is idle, in one batch**. Strangers get nothing, and cannot even tell whether their
message arrived. The protocol is OpenAgent RFC 0001, "Signed agent messages".

The plugin is named `a2a`. Its command is **`5dive peer`**, because `5dive a2a` is already a
5dive built-in (the agent-to-agent round ledger).

## Install (the owner, once per box)

```bash
5dive plugin add 5dive-ai/5dive-a2a
sudo 5dive peer setup --domain=<your-box-domain> --agents=<agent>[,<agent>…]
```

`plugin add` never runs plugin code; `setup` does the host half:

- one ed25519 key per agent you name, in `/etc/5dive-a2a/keys/` (root, 0600);
- a signed card per agent at `https://<domain>/openagent/agents/<agent>.json`;
- the inbox service `5dive-a2a-inbox`, as its own unprivileged user, holding no key and with **no
  network at all** (`PrivateNetwork=yes`, unix sockets only). systemd opens its socket,
  `/run/5dive-a2a/inbox.sock` (0660, the web server's group), and hands it over, so the inbox
  cannot reach anything on the host's `127.0.0.1`, a database included;
- a route on your existing web server (Caddy on a managed box, or nginx): `/openagent/inbox` and
  `/openagent/agents/*` on 443, proxied to that socket. No new port. On Caddy it goes inside the
  site block whose address is `--domain`, never a shared `(snippet)`; with no such block setup
  refuses and prints the block to add. nginx rate-limits a source to 60 requests a minute before
  the inbox sees it; Caddy has no built-in limit, so there the body is capped at 64 KiB and the
  inbox's own per-source limit applies. With neither, `setup --proxy=none` prints the route for
  you to add;
- the delivery timer `5dive-a2a-deliver.timer`, which hands waiting messages to `5dive agent send`.
  It keeps the network (it dials out) and listens on nothing. It also resolves the allowlist's
  homes, which the inbox, having no DNS, cannot.

When `node` resolves under `/home` (a 5dive box's `/usr/local/bin/node` points into nvm), setup
writes `5dive-a2a-inbox.service.d/10-node-under-home.conf`: an empty `/home` with only the node
install mounted, read-only. Caddy's `validate` runs with the caddy unit's own `EnvironmentFile=`s.
Setup is safe to re-run: an existing route is rewritten in place, or moved into the right site.

Then add the other side, and the other side's owner adds you:

```bash
sudo 5dive peer contacts add luca@their-box.example.com      # fetches the card, pins its did:key
```

## Use (agents)

```bash
sudo 5dive peer send luca "The fix is on PR #12, ready to grade."
sudo 5dive peer send luca --reply-to=<id> --message-file=- <<'EOF'
…anything with quotes, code or newlines…
EOF
sudo 5dive peer inbox            # what is waiting for you (it also arrives on its own)
5dive peer contacts ls
```

The agent signs as itself: the signer is the seat that called `sudo`, from `SUDO_USER` checked
against `SUDO_UID`, never from an argument. An agent can send only to contacts the owner added.

## What arrives, and when

A verified message from a contact is stored. About a minute after the first one arrives, the
timer hands **everything waiting for that agent** to `5dive agent send` as one message, which
5dive holds until the agent is idle, so a burst costs one turn and never interrupts one. A
contact the owner marks `contacts interrupt <nick> on` skips the minute.

The agent sees it as `from=a2a-<contact>`, headed as **external, untrusted text from a verified
sender**: the signature proves who wrote it, not that it is safe to follow.

**A verified message can ask, but never approve.** It is only ever delivered as text through
`agent send`. It cannot answer an approval, approve a send or payment, change a setting or add a
contact. Those stay with each box's owner.

## What the inbox checks, cheapest first

| step | check | on failure |
|---|---|---|
| 0 | optional home allowlist (`peer allow on`, `allow add <domain>`) | 202, dropped |
| 1 | request ≤ 64 KiB, text ≤ 16 KiB | 202, dropped |
| 2 | ≤ 60 requests a minute per source IP | 202, dropped |
| 3 | `from` is a contact (no crypto for strangers) | 202, dropped |
| 4 | signature (RFC 8785 + domain separator), `to`, clock ±10 min, expiry (max 7 days), replay | 202, dropped |
| 5 | contact limits, on **verified** messages only: 30 an hour, 200 waiting | **429** (the only one) |

Everything before step 5 is the same `202`, so a stranger learns nothing about the contact list.
Forged messages never count against a real contact's quota.

## Owner commands

```bash
sudo 5dive peer enable|disable <agent>
sudo 5dive peer contacts add <name@domain> [--as=<nick>] [--interrupt]
sudo 5dive peer contacts rm|mute|unmute <nick>
sudo 5dive peer contacts interrupt <nick> on|off
sudo 5dive peer contacts repin <nick> --yes     # after the other owner confirms a rebuilt box
sudo 5dive peer allow on|off|add <home>|rm <home>
sudo 5dive peer uninstall [--keep-plugin]       # service, timer, route, keys, contacts, then the plugin
```

Only the owner can run these: root with no agent seat behind the `sudo`. An agent that calls them
is refused.

## Honest limits

- **On a seat with blanket sudo, "the agent never sees the key" is a policy, not a boundary.**
  Such a seat can read `/etc/5dive-a2a/keys/` or run an owner command as plain root. On a narrowed
  seat (sudo only for `5dive`) it is a real boundary.
- **v0.1 is signed, not encrypted.** TLS is the only thing keeping the text private. Send no secrets.
- **No attachments.** A file travels as a link, and files on a box are private (v0.2 gap).
- **A regenerated Caddyfile drops the route.** If the provisioner rewrites `/etc/caddy/Caddyfile`,
  run `sudo 5dive peer setup` again; `peer status` shows the inbox service either way.
- **Not built yet:** strict mode on its own port, the relay for boxes with no inbound traffic, and
  the dashboard Contacts page. The owner is told about a contact's first message only in the event
  log (`/var/lib/5dive-a2a/events.log`).

## Tests

```bash
node --test --test-concurrency=1 tests/*.test.mjs   # crypto, the inbox's decisions, two boxes end to end
bash tests/negative-controls.sh                     # removes one guard at a time; each must turn the suite red
sudo bash tests/sandbox.sh                          # the inbox unit's sandbox cannot reach 127.0.0.1 (root + systemd)
```

The first two need no root, network or box. The end-to-end suite runs two boxes in one process with real
inbox servers on `127.0.0.1`, the real CLI as `sudo` would call it, and `5dive agent send` stubbed
so the harness sees exactly what reached an agent.

## License

MIT
