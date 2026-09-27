// Where 5dive-a2a keeps things, and the file-backed store the inbox uses.
//
//   /etc/5dive-a2a/            root:5dive-a2a 0750 — its OWN top-level dir: /etc/5dive is
//                              0750 root:claude on a 5dive host, so the inbox user could not traverse it
//     config.json              domain, inbox url, port, which agents are on, allowlist
//     contacts.json            root:5dive-a2a 0640 — the trust root; only the owner writes it
//     keys/<agent>.key         root:root 0600 — never readable by the inbox service or a seat
//     cards/<agent>.json       0644 — the signed card, served at /openagent/agents/<agent>.json
//   /var/lib/5dive-a2a/        5dive-a2a 0750 — written by the inbox service (not under
//                              /var/lib/5dive, which is 2750 root:claude)
//     spool/<id>.json          verified messages waiting for delivery
//     seen.json                message ids until they expire (replay guard)
//     counts.json              verified-message times per contact (last hour)
//     events.log               jsonl: skew, rate, backlog, first contact, delivery
//     outbox.log               jsonl: what this box's agents sent (root writes)
//     allow-ips.json           the allowlist's homes, resolved by root (the inbox has no network)
//
// Test seam: A2A_ETC and A2A_VAR move both trees, and are honoured ONLY in a
// process that is not root. Through `sudo` they would be a way to point a
// root verb at a seat-written tree, so root always uses the fixed paths.
import fs from "node:fs";
import path from "node:path";

const isRoot = () => typeof process.geteuid === "function" && process.geteuid() === 0;

export function paths() {
  const etc = (!isRoot() && process.env.A2A_ETC) || "/etc/5dive-a2a";
  const v = (!isRoot() && process.env.A2A_VAR) || "/var/lib/5dive-a2a";
  return {
    etc, var: v,
    config: path.join(etc, "config.json"),
    contacts: path.join(etc, "contacts.json"),
    keys: path.join(etc, "keys"),
    cards: path.join(etc, "cards"),
    spool: path.join(v, "spool"),
    seen: path.join(v, "seen.json"),
    counts: path.join(v, "counts.json"),
    events: path.join(v, "events.log"),
    outbox: path.join(v, "outbox.log"),
    delivered: path.join(v, "delivered.json"),
    allowIps: path.join(v, "allow-ips.json"),
  };
}

export function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return fallback; }
}

// readJson for the inbox's trust root: a MISSING file is the fallback, but one that is
// there and cannot be read (EACCES, a torn write) throws. Treating it as empty turned
// every contact into a stranger, silently (DIVE-5064).
export function readJsonStrict(file, fallback) {
  let text;
  try { text = fs.readFileSync(file, "utf8"); } catch (e) {
    if (e && e.code === "ENOENT") return fallback;
    throw Object.assign(new Error(`cannot read ${file}: ${e && e.code}`), { file, code: e && e.code });
  }
  try { return JSON.parse(text); } catch { throw Object.assign(new Error(`cannot parse ${file}`), { file, code: "EPARSE" }); }
}

// Atomic write: temp file in the same directory, then rename. The rename puts a NEW
// inode in place, owned by whoever wrote it, so the temp file first takes the owner of
// the file it replaces (or `owner`, {uid, gid}): root rewriting contacts.json must not
// take it away from the inbox's group (DIVE-5064).
export function writeJson(file, value, mode = 0o640, owner) {
  const tmp = `${file}.tmp-${process.pid}`;
  if (!owner) { try { const st = fs.statSync(file); owner = { uid: st.uid, gid: st.gid }; } catch { /* a new file */ } }
  const fd = fs.openSync(tmp, "w", mode);
  try {
    fs.writeSync(fd, JSON.stringify(value, null, 2) + "\n");
    if (owner) {
      try { fs.fchownSync(fd, owner.uid, owner.gid); } catch (e) {
        // Only root can give a file away; a non-root writer (the inbox, the tests) keeps its own.
        if (isRoot() || !e || e.code !== "EPERM") throw e;
      }
    }
  } catch (e) { fs.closeSync(fd); fs.rmSync(tmp, { force: true }); throw e; }
  fs.closeSync(fd);
  fs.renameSync(tmp, file);
}

// config.json and contacts.json take the owner of /etc/5dive-a2a (root:5dive-a2a once
// `peer setup` installed the service), so a write also heals a file an older version
// left root:root.
export function etcOwner(p = paths()) {
  try { const st = fs.statSync(p.etc); return { uid: st.uid, gid: st.gid }; } catch { return undefined; }
}

export function appendLog(file, obj) {
  try { fs.appendFileSync(file, JSON.stringify(obj) + "\n", { mode: 0o640 }); } catch { /* logging never blocks */ }
}

export function loadConfig(p = paths()) {
  return readJson(p.config, null);
}

export function loadContacts(p = paths()) {
  const doc = readJson(p.contacts, { contacts: [] });
  return Array.isArray(doc.contacts) ? doc.contacts : [];
}

export function saveContacts(list, p = paths()) {
  writeJson(p.contacts, { contacts: list }, 0o640, etcOwner(p));
}

export function saveConfig(config, p = paths()) {
  writeJson(p.config, config, 0o640, etcOwner(p));
}

// The inbox's store: seen ids and counts persist across restarts, the per-IP
// window is memory only.
export function fileStore(p = paths()) {
  fs.mkdirSync(p.spool, { recursive: true, mode: 0o750 });
  let seen = readJson(p.seen, {});
  let counts = readJson(p.counts, {});
  const ipWin = new Map();
  const prune = (now) => {
    for (const [id, exp] of Object.entries(seen)) if (exp <= now) delete seen[id];
    for (const [did, times] of Object.entries(counts)) {
      counts[did] = times.filter((t) => t > now - 3600 * 1000);
      if (!counts[did].length) delete counts[did];
    }
  };
  return {
    ipHit(ip, now) {
      const w = (ipWin.get(ip) || []).filter((t) => t > now - 60 * 1000);
      w.push(now);
      ipWin.set(ip, w);
      if (ipWin.size > 10000) for (const k of ipWin.keys()) { ipWin.delete(k); if (ipWin.size < 5000) break; }
      return w.length;
    },
    seen(id) { return Object.prototype.hasOwnProperty.call(seen, id); },
    verifiedCount(did, since) { return (counts[did] || []).filter((t) => t > since).length; },
    waitingCount(did) {
      let n = 0;
      for (const f of fs.readdirSync(p.spool)) {
        if (!f.endsWith(".json")) continue;
        const r = readJson(path.join(p.spool, f), null);
        if (r && r.from_did === did) n++;
      }
      return n;
    },
    accept(record) {
      prune(record.received_at);
      seen[record.id] = record.expires_at;
      (counts[record.from_did] ||= []).push(record.received_at);
      writeJson(path.join(p.spool, `${record.id}.json`), record, 0o640);
      writeJson(p.seen, seen, 0o640);
      writeJson(p.counts, counts, 0o640);
    },
    log(event) { appendLog(p.events, event); },
  };
}

export function listSpool(p = paths()) {
  let files = [];
  try { files = fs.readdirSync(p.spool).filter((f) => f.endsWith(".json")); } catch { return []; }
  return files.map((f) => ({ file: path.join(p.spool, f), rec: readJson(path.join(p.spool, f), null) }))
    .filter((x) => x.rec)
    .sort((a, b) => a.rec.received_at - b.rec.received_at);
}
