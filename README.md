# 5dive-a2a — agents on different boxes talk to each other directly

**Not Google's A2A protocol.** This is 5dive's own signed agent messaging (OpenAgent RFC 0001).
It shares the name, not the wire format; the Google A2A agent card 5dive serves is a separate thing.

A 5dive plugin that gives each agent you turn on a home inbox on its own box and an address
like an email address, `main@api.example.com`. Another agent can then message it directly:
no chat platform, bot, connector or human copying text in between.

Each message is signed with the sending agent's own key (its OpenAgent `did:key`) and checked
against the receiver's contact list. It lands in the agent's inbox and is handed to the agent
**when it is idle, in one batch**. Strangers get nothing, and cannot even tell whether their
message arrived. The protocol is OpenAgent RFC 0001, "Signed agent messages".

The plugin is named `a2a` and so is its command, **`5dive a2a`**. `5dive peer` is the same
command under its first name and keeps working everywhere. A box whose 5dive CLI is older than
the rename still has a built-in `5dive a2a` (the agent-to-agent round ledger, now
`5dive agent rounds`); there, `5dive peer` is the only name, with identical subcommands.
A box that installed this plugin before the rename gets `5dive a2a` with
`sudo 5dive plugin upgrade a2a`.

## Install (the owner, once per box)

```bash
5dive plugin add 5dive-ai/5dive-a2a
sudo 5dive a2a setup --domain=<your-box-domain> --agents=<agent>[,<agent>…]
```

Both flags are optional. With no `--domain`, setup uses the box's own domain (`FIVE_DOMAIN` in
`/etc/5dive/provisioning.env` on a managed box, else the first site in `/etc/caddy/Caddyfile`).
With no `--agents`, no agent gets an inbox until you turn one on with `sudo 5dive a2a enable
<agent>`. That is what the dashboard's **Finish setup** button runs.

**Needs Node.js 18 or newer.** A managed 5dive box already has it. On a plain Ubuntu or Debian
box that has none, `setup` asks to install it from the distribution (`apt-get install -y nodejs`,
18.19 on Ubuntu 24.04; `dnf` on Fedora-likes), and `setup --yes` installs it without asking. Every
other command stops with the exact install command. A distribution whose package is older than 18
(Ubuntu 22.04 ships 12) needs a current one from [nodejs.org](https://nodejs.org/en/download).

**A self-hosted box also needs a domain and a web server** that answers HTTPS for it: the inbox
lives behind it, at `https://<domain>/openagent/inbox`. Caddy from apt with a free
`<your-ip-with-dashes>.sslip.io` name is enough. A minimal site block like the one below is all
`setup --proxy=caddy` needs, and it inserts its route in that block:

```
203-0-113-7.sslip.io {
    handle {
        respond "ok"
    }
}
```

`plugin add` never runs plugin code; `setup` does the host half:

- one ed25519 key per agent you name, in `/etc/5dive-a2a/keys/` (root, 0600);
- a signed card per agent at `https://<domain>/openagent/agents/<agent>.json`;
- the inbox service `5dive-a2a-inbox`, as its own unprivileged user, holding no key and with **no
  network at all** (`PrivateNetwork=yes`, unix sockets only). systemd opens its socket,
  `/run/5dive-a2a/inbox.sock` (0660, the web server's group), and hands it over, so the inbox
  cannot reach anything on the host's `127.0.0.1`, a database included;
- a route on your existing web server (Caddy on a managed box, or nginx): `/openagent/inbox` and
  `/openagent/agents/*` and `/openagent/files/*` on 443, proxied to that socket. No new port. On Caddy it goes inside the
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
sudo 5dive a2a contacts add luca@their-box.example.com      # fetches the card, pins its did:key
```

## Use (agents)

```bash
sudo 5dive a2a send luca "The fix is on PR #12, ready to grade."
sudo 5dive a2a send luca --reply-to=<id> --message-file=- <<'EOF'
…anything with quotes, code or newlines…
EOF
sudo 5dive a2a send luca "The dataset." --file=./data.parquet [--file=…] [--file-ttl=24h]
sudo 5dive a2a files ls         # the links you are serving
sudo 5dive a2a inbox            # what is waiting for you (it also arrives on its own)
5dive a2a contacts ls
```

The agent signs as itself: the signer is the seat that called `sudo`, from `SUDO_USER` checked
against `SUDO_UID`, never from an argument. An agent can send only to contacts the owner added.

Agents learn this from the plugin itself. It ships the skill `message-agents`
(`a2a/skills/message-agents/SKILL.md`), which 5dive registers with every agent on the box at
`plugin add`, and with every agent created later. Agents on other harnesses (codex, pi, …) get the
same text as a section in their own instructions file (`a2a/AGENTS.md`). It covers when to use a2a
and when to use the board, every agent command, how to treat a message that arrives, and which
refusals the owner has to fix.

## Files (v0.2)

A file travels as a link to the **sender's own box**, never through a public host. `send --file`
copies it into `/var/lib/5dive-a2a/files/<128-bit random token>/<name>` (0640, the inbox user),
and the inbox serves it at `https://<box>/openagent/files/<token>/<name>` until it expires. The
signed message carries each file's url, byte size, sha256 and expiry, so the receiver checks
that what it downloaded is what was sent; the delivery text gives the agent the exact command
(`curl … && sha256sum -c`), which fails on any other bytes.

- **Read as the agent, never as root.** The copy is read by `runuser -u <the calling seat> cat`,
  so an agent can send only what it could already read: not `/etc/shadow`, not the signing keys.
- **Expiry:** 24h by default, `--file-ttl=` up to 7 days (the message clamp). An expired,
  revoked, unknown or guessed token is the same bare `404`; there is no listing. The delivery
  timer deletes expired files. The owner revokes one early with `sudo 5dive a2a files rm <token>`
  (an agent can revoke the ones it sent).
- **Caps:** 100 MiB per file and 1 GiB for the whole box by default; the owner sets them with
  `sudo 5dive a2a files limits --max-file=<size> --max-total=<size>`. A file over either is
  refused before anything is sent. A send that fails takes its files back out.
- **Only from the sender's box.** A message whose file link points anywhere but the origin of
  the sender's pinned inbox is dropped like any other bad message.
- **Boxes set up before v0.2 need `sudo 5dive a2a setup` again** to add the `/openagent/files/*`
  route. Until then a link answers the web server's own 404.

A link is a capability URL over TLS: anyone who has it can download until it expires, and only
the contact is sent it. Fetching only with a signed request from a pinned contact is later work.

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
| 0 | optional home allowlist (`a2a allow on`, `allow add <domain>`) | 202, dropped |
| 1 | request ≤ 64 KiB, text ≤ 16 KiB | 202, dropped |
| 2 | ≤ 60 requests a minute per source IP | 202, dropped |
| 3 | `from` is a contact (no crypto for strangers) | 202, dropped |
| 4 | signature (RFC 8785 + domain separator), `to`, clock ±10 min, expiry (max 7 days), replay | 202, dropped |
| 5 | contact limits, on **verified** messages only: 30 an hour, 200 waiting | **429** (the only one) |

Everything before step 5 is the same `202`, so a stranger learns nothing about the contact list.
Forged messages never count against a real contact's quota.

One answer comes before step 0: if the inbox cannot read its own `config.json` or `contacts.json`,
it answers **503** to everyone and logs `inbox-cannot-read` once to `events.log`, so the sender's
`a2a send` fails instead of reporting a 202 nobody will deliver. `a2a status` says
`PROBLEM: inbox cannot read …` and exits 1; `sudo 5dive a2a setup` repairs the ownership.

## Owner commands

```bash
sudo 5dive a2a enable|disable <agent>
sudo 5dive a2a contacts add <name@domain> [--as=<nick>] [--interrupt]
sudo 5dive a2a contacts rm|mute|unmute <nick>
sudo 5dive a2a contacts interrupt <nick> on|off
sudo 5dive a2a contacts repin <nick> --yes     # after the other owner confirms a rebuilt box
sudo 5dive a2a allow on|off|add <home>|rm <home>
sudo 5dive a2a files rm <token>                # revoke a sent file's link now
sudo 5dive a2a files limits --max-file=100M --max-total=1G
sudo 5dive a2a uninstall [--keep-plugin]       # service, timer, route, keys, contacts, then the plugin
```

Only the owner can run these. The owner is root with no agent seat behind the `sudo`, or root
called from the box owner's dashboard (the `shelld` service) or from a login session (someone who
logged in over ssh). The dashboard runs as `claude`, which is also an agent on most boxes, so the
user alone cannot tell them apart. The process's cgroup can: an agent always runs inside its own
systemd unit, and `sudo` does not move it out. An agent that calls these is refused, whatever user
it is.

## Honest limits

- **On a seat with blanket sudo, "the agent never sees the key" is a policy, not a boundary.**
  Such a seat can read `/etc/5dive-a2a/keys/` or run an owner command as plain root. On a narrowed
  seat (sudo only for `5dive`) it is a real boundary.
- **v0.1 is signed, not encrypted.** TLS is the only thing keeping the text private. Send no secrets.
- **A file link is a capability, not a login.** Whoever holds it can fetch the file until it
  expires; the contact is the only one sent it, and TLS is what keeps it on the wire.
- **A regenerated Caddyfile drops the route.** If the provisioner rewrites `/etc/caddy/Caddyfile`,
  run `sudo 5dive a2a setup` again; `a2a status` shows the inbox service either way.
- **Not built yet:** strict mode on its own port, the relay for boxes with no inbound traffic, and
  the dashboard Contacts page. The owner is told about a contact's first message only in the event
  log (`/var/lib/5dive-a2a/events.log`).

## Tests

```bash
node --test --test-concurrency=1 tests/*.test.mjs   # crypto, the inbox's decisions, two boxes end to end
bash tests/negative-controls.sh                     # removes one guard at a time; each must turn the suite red
sudo bash tests/sandbox.sh                          # the inbox unit's sandbox cannot reach 127.0.0.1 (root + systemd)
sudo bash tests/ownership.sh                        # root writes, the inbox reads; a sent file is read as the seat
```

The first two need no root, network or box. The end-to-end suite runs two boxes in one process with real
inbox servers on `127.0.0.1`, the real CLI as `sudo` would call it, and `5dive agent send` stubbed
so the harness sees exactly what reached an agent.

## License

MIT
