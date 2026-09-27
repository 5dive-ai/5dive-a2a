// The inbox service. Runs as the unprivileged `5dive-a2a` user on 127.0.0.1,
// behind the box's own web server (Caddy or nginx) on 443. It holds no private
// key: it only verifies, stores and answers. Delivery into an agent is the
// root timer's job (`5dive peer _tick`), so this process never reaches a seat.
//
//   POST /openagent/inbox               -> receive() -> always 202, or 429 after verify
//   GET  /openagent/agents/<name>.json  -> the signed card
import http from "node:http";
import dns from "node:dns/promises";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MAX_REQUEST_BYTES } from "./core.mjs";
import { receive, DEFAULT_LIMITS } from "./receiver.mjs";
import { paths, readJson, fileStore, loadContacts } from "./state.mjs";

// The proxy in front is the only peer allowed to name the client. Its own
// address is loopback, and our snippet OVERWRITES X-Forwarded-For with the
// client it saw, so the last entry is the one the proxy wrote.
export function clientIp(req) {
  const peer = (req.socket.remoteAddress || "").replace(/^::ffff:/, "");
  const loop = peer === "127.0.0.1" || peer === "::1";
  const xff = req.headers["x-forwarded-for"];
  if (loop && typeof xff === "string" && xff.trim()) {
    const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
    return parts[parts.length - 1].replace(/^::ffff:/, "");
  }
  return peer;
}

export function buildContext(p = paths()) {
  const config = readJson(p.config, {}) || {};
  const contacts = new Map();
  for (const c of loadContacts(p)) contacts.set(c.did, c);
  const agents = new Map();
  for (const [name, a] of Object.entries(config.agents || {})) if (a && a.inbox && a.did) agents.set(a.did, name);
  return { config, contacts, agents, limits: { ...DEFAULT_LIMITS, ...(config.limits || {}) } };
}

async function resolveHomes(homes) {
  const ips = new Set();
  for (const h of homes || []) {
    const host = String(h).replace(/:\d+$/, "");
    if (/^[\d.]+$/.test(host) || host.includes(":")) { ips.add(host); continue; }
    for (const fam of [4, 6]) {
      try { for (const r of await dns.lookup(host, { all: true, family: fam })) ips.add(r.address); } catch { /* a home that does not resolve is simply not on the list */ }
    }
  }
  return ips;
}

export function createInbox({ p = paths(), store = fileStore(p), now = () => Date.now(), resolve = resolveHomes } = {}) {
  let ctx = buildContext(p);
  let stamp = "";
  let allow = null;
  let allowAt = 0;
  const refresh = async () => {
    // Re-read config and contacts when either file changes, so an owner's
    // `contacts rm` takes effect on the next message, with no restart.
    const s = [p.config, p.contacts].map((f) => { try { return fs.statSync(f).mtimeMs; } catch { return 0; } }).join(":");
    if (s !== stamp) { ctx = buildContext(p); stamp = s; allowAt = 0; }
    const al = ctx.config.allowlist;
    if (!al || !al.enabled) { allow = null; return; }
    // Homes move, so they are re-resolved every few minutes.
    if (now() - allowAt > 5 * 60 * 1000) { allow = await resolve(al.homes); allowAt = now(); }
  };

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
    try { await refresh(); } catch { /* keep the last good context */ }
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
  const p = paths();
  const config = readJson(p.config, {}) || {};
  const port = Number(config.port) || 7461;
  createInbox({ p }).listen(port, "127.0.0.1", () => {
    process.stdout.write(`5dive-a2a inbox on 127.0.0.1:${port}\n`);
  });
}
