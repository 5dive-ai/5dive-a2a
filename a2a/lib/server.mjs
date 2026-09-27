// The inbox service. Runs as the unprivileged `5dive-a2a` user with no network
// (PrivateNetwork=yes): it serves the unix socket systemd hands it, behind the
// box's own web server (Caddy or nginx) on 443. It holds no private key: it only
// verifies, stores and answers. Delivery into an agent is the root timer's job
// (`5dive peer _tick`), so this process never reaches a seat.
//
//   POST /openagent/inbox               -> receive() -> always 202, or 429 after verify
//   GET  /openagent/agents/<name>.json  -> the signed card
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MAX_REQUEST_BYTES } from "./core.mjs";
import { receive, DEFAULT_LIMITS } from "./receiver.mjs";
import { paths, readJson, readJsonStrict, fileStore } from "./state.mjs";

const INBOX_SOCKET = "/run/5dive-a2a/inbox.sock";

// The proxy in front is the only peer allowed to name the client. On the unix
// socket it is the only peer at all (0660, the web server's group); over TCP (the
// harness) it is loopback. Our proxy config OVERWRITES X-Forwarded-For with the
// client it saw, so the last entry is the one the proxy wrote.
export function clientIp(req) {
  const peer = (req.socket.remoteAddress || "").replace(/^::ffff:/, "");
  const loop = !peer || peer === "127.0.0.1" || peer === "::1";
  const xff = req.headers["x-forwarded-for"];
  if (loop && typeof xff === "string" && xff.trim()) {
    const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
    return parts[parts.length - 1].replace(/^::ffff:/, "");
  }
  return peer;
}

// Throws when config.json or contacts.json is there but unreadable: an empty contact list
// would make every contact a stranger, dropped with the same 202 (DIVE-5064).
export function buildContext(p = paths()) {
  const config = readJsonStrict(p.config, {}) || {};
  const doc = readJsonStrict(p.contacts, { contacts: [] }) || {};
  const contacts = new Map();
  for (const c of Array.isArray(doc.contacts) ? doc.contacts : []) contacts.set(c.did, c);
  const agents = new Map();
  for (const [name, a] of Object.entries(config.agents || {})) if (a && a.inbox && a.did) agents.set(a.did, name);
  return { config, contacts, agents, limits: { ...DEFAULT_LIMITS, ...(config.limits || {}) } };
}

export function createInbox({ p = paths(), store = fileStore(p), now = () => Date.now() } = {}) {
  let ctx = null;
  let stamp = "";
  let allow = null;
  let broken = "";
  const refresh = () => {
    // Re-read config, contacts and the resolved allowlist when any file changes, so an
    // owner's `contacts rm` takes effect on the next message, with no restart. The stamp
    // is inode + ctime + mtime: a rename is a new inode, and a chgrp/chmod heal moves
    // only the ctime (DIVE-5064).
    const s = [p.config, p.contacts, p.allowIps].map((f) => { try { const st = fs.statSync(f); return `${st.ino}.${st.ctimeMs}.${st.mtimeMs}`; } catch (e) { return e && e.code; } }).join(":");
    if (s === stamp) return;
    try { ctx = buildContext(p); } catch (e) {
      // Fail closed: no stale contact list (a removed contact must not get back in), and
      // the owner is told once per new failure, not once per message.
      ctx = null; allow = null; stamp = s;
      if (e.message !== broken) store.log({ at: now(), event: "inbox-cannot-read", file: e.file, error: e.code || String(e.message) });
      broken = e.message;
      return;
    }
    stamp = s;
    if (broken) store.log({ at: now(), event: "inbox-can-read", file: p.contacts });
    broken = "";
    const al = ctx.config.allowlist;
    // Root resolves the homes (this process has no DNS); on with no file yet refuses all.
    allow = al && al.enabled ? new Set((readJson(p.allowIps, null) || { ips: [] }).ips) : null;
  };
  try { refresh(); } catch { /* the first request tries again */ }

  const server = http.createServer(async (req, res) => {
    const url = (req.url || "").split("?")[0];
    const card = /^\/openagent\/agents\/([a-z][a-z0-9-]{0,31})\.json$/.exec(url);
    if (req.method === "GET" && card) {
      const file = path.join(p.cards, `${card[1]}.json`);
      let body;
      try { body = fs.readFileSync(file); } catch { res.writeHead(404).end(); return; }
      res.writeHead(200, { "content-type": "application/json", "cache-control": "max-age=300" }).end(body);
      return;
    }
    if (url !== "/openagent/inbox") { res.writeHead(404).end(); return; }
    if (req.method !== "POST") { res.writeHead(405, { allow: "POST" }).end(); return; }

    // Keep at most the cap. Past it, keep nothing and answer like any other drop
    // (the same 202); past 1 MiB, stop listening altogether.
    const bytes = await new Promise((resolve) => {
      const chunks = [];
      let size = 0, over = false;
      req.on("data", (c) => {
        size += c.length;
        if (size > MAX_REQUEST_BYTES) {
          over = true; chunks.length = 0;
          if (size > 1024 * 1024) { req.destroy(); resolve(null); }
        } else chunks.push(c);
      });
      req.on("end", () => resolve(over ? null : Buffer.concat(chunks)));
      req.on("error", () => resolve(null));
    });
    try { refresh(); } catch { /* keep the last good context */ }
    // The inbox cannot read its own trust root: say so (503, the same to everyone, before
    // any check), so the sender's `peer send` fails instead of reporting a 202 that
    // nobody will ever deliver.
    if (!ctx) { res.writeHead(503, { "content-type": "application/json", connection: "close" }).end('{"status":"unavailable"}'); return; }
    let result;
    try {
      result = receive({ ip: clientIp(req), bytes, now: now() }, { ...ctx, allow, store });
    } catch (e) {
      store.log({ at: now(), event: "inbox-error", error: String(e && e.message) });
      result = { status: 202, outcome: "drop:error" };
    }
    res.writeHead(result.status, { "content-type": "application/json", connection: "close" })
      .end(result.status === 429 ? '{"status":"rate-limited"}' : '{"status":"accepted"}');
  });
  return server;
}

// `node server.mjs` — the unit's ExecStart.
const isEntry = () => { try { return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } };
if (isEntry()) {
  // 5dive-a2a-inbox.socket passes fd 3 (sd_listen_fds); this process opens no socket itself.
  const fromSystemd = process.env.LISTEN_PID === String(process.pid) && Number(process.env.LISTEN_FDS) >= 1;
  const where = fromSystemd ? { fd: 3 } : { path: INBOX_SOCKET };
  createInbox({ p: paths() }).listen(where, () => {
    process.stdout.write(`5dive-a2a inbox on ${fromSystemd ? "the systemd socket" : INBOX_SOCKET}\n`);
  });
}
