// What setup writes to systemd, and what it reads back from it (DIVE-5061): node under
// /home, the caddy unit's environment, the inbox with no network, and the allowlist the
// inbox can no longer resolve for itself.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { unitText, nodeDropIn, resolveNode, parseEnvFile, unitEnv, resolveHomes, refreshAllow, INBOX_SOCKET } from "../a2a/lib/cli.mjs";
import { clientIp } from "../a2a/lib/server.mjs";
import { paths } from "../a2a/lib/state.mjs";

const service = (text) => text.split("[Service]")[1].split("\n[")[0];

test("the inbox unit has no network: PrivateNetwork, unix sockets only, no IPAddressAllow", () => {
  const u = unitText("/usr/bin/node", { socketGroup: "caddy" });
  const inbox = service(u["5dive-a2a-inbox.service"]);
  assert.match(inbox, /^PrivateNetwork=yes$/m);
  assert.match(inbox, /^RestrictAddressFamilies=AF_UNIX$/m);
  assert.doesNotMatch(u["5dive-a2a-inbox.service"], /IPAddressAllow/);
  assert.match(u["5dive-a2a-inbox.service"], /^Requires=5dive-a2a-inbox\.socket$/m);
  const sock = u["5dive-a2a-inbox.socket"];
  assert.match(sock, new RegExp(`^ListenStream=${INBOX_SOCKET}$`, "m"));
  assert.match(sock, /^SocketGroup=caddy$/m);
  assert.match(sock, /^SocketMode=0660$/m, "the web server's group, not every local user");
  assert.doesNotMatch(u["5dive-a2a-deliver.service"], /Listen|Socket/, "delivery listens on nothing");
});

test("node under /home: resolved through the symlink, and bound read-only into an empty /home", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a2a-node-"));
  fs.mkdirSync(path.join(dir, "v24/bin"), { recursive: true });
  fs.writeFileSync(path.join(dir, "v24/bin/node"), "");
  fs.symlinkSync(path.join(dir, "v24/bin/node"), path.join(dir, "node"));
  assert.equal(resolveNode(path.join(dir, "node")), fs.realpathSync(path.join(dir, "v24/bin/node")));
  assert.equal(resolveNode(""), "/usr/bin/node");
  fs.rmSync(dir, { recursive: true, force: true });

  const d = nodeDropIn("/home/claude/.nvm/versions/node/v24.21.0/bin/node");
  assert.match(d, /^\[Service\]$/m);
  assert.match(d, /^ProtectHome=tmpfs$/m);
  assert.match(d, /^BindReadOnlyPaths=\/home\/claude\/\.nvm\/versions\/node\/v24\.21\.0$/m);
  assert.doesNotMatch(d, /^ExecStart/m, "the unit's own ExecStart already names the resolved path");
  assert.equal(nodeDropIn("/usr/bin/node"), null);
  assert.equal(nodeDropIn("/opt/node/bin/node"), null);
  assert.match(unitText("/home/claude/.nvm/versions/node/v24.21.0/bin/node")["5dive-a2a-inbox.service"], /^ExecStart=\/home\/claude\/\.nvm\/versions\/node\/v24\.21\.0\/bin\/node /m);
});

test("caddy validate gets the caddy unit's environment (cf-dns.env)", () => {
  assert.deepEqual(parseEnvFile("# token\nCF_API_TOKEN=abc\nexport Q='x y'\n  \nBAD LINE\nE=\"1=2\"\n"), { CF_API_TOKEN: "abc", Q: "x y", E: "1=2" });
  const files = { "/etc/caddy/cf-dns.env": "CF_API_TOKEN=tok\n", "/etc/caddy/more.env": "A=from-file\n" };
  const show = "Environment=A=inline \"B=two words\"\nEnvironmentFiles=/etc/caddy/cf-dns.env (ignore_errors=no)\nEnvironmentFiles=/etc/caddy/more.env (ignore_errors=yes)\nEnvironmentFiles=/missing (ignore_errors=yes)\n";
  assert.deepEqual(unitEnv(show, (f) => { if (!(f in files)) throw new Error("ENOENT"); return files[f]; }), { A: "from-file", B: "two words", CF_API_TOKEN: "tok" });
  assert.deepEqual(unitEnv("Environment=\nEnvironmentFiles=\n"), {});
});

test("behind the unix socket the proxy is the only peer, so its X-Forwarded-For is the client", () => {
  const req = (remoteAddress, xff) => ({ socket: { remoteAddress }, headers: xff ? { "x-forwarded-for": xff } : {} });
  assert.equal(clientIp(req(undefined, "192.0.2.9")), "192.0.2.9");
  assert.equal(clientIp(req(undefined, "192.0.2.1, 192.0.2.9")), "192.0.2.9");
  assert.equal(clientIp(req("127.0.0.1", "192.0.2.9")), "192.0.2.9");
  assert.equal(clientIp(req("192.0.2.4", "192.0.2.9")), "192.0.2.4", "a non-proxy peer cannot name the client");
});

test("the allowlist is resolved by root and read by the inbox, which has no DNS", async () => {
  const lookup = async (h, o) => (h === "home.example.com" ? [{ address: o.family === 4 ? "192.0.2.7" : "::ffff:192.0.2.77" }] : Promise.reject(new Error("ENOTFOUND")));
  assert.deepEqual(await resolveHomes(["home.example.com", "192.0.2.1", "gone.example.com"], lookup), ["192.0.2.7", "::ffff:192.0.2.77", "192.0.2.1"]);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "a2a-allow-"));
  process.env.A2A_ETC = path.join(root, "etc"); process.env.A2A_VAR = path.join(root, "var");
  const p = paths();
  fs.mkdirSync(p.var, { recursive: true });
  const config = { allowlist: { enabled: true, homes: ["home.example.com"] } };
  const first = await refreshAllow(p, config, { now: 1000, lookup });
  assert.deepEqual(JSON.parse(fs.readFileSync(p.allowIps, "utf8")).ips, ["192.0.2.7", "::ffff:192.0.2.77"]);
  let calls = 0;
  const counting = async (...x) => { calls++; return lookup(...x); };
  assert.deepEqual(await refreshAllow(p, config, { now: 2000, lookup: counting }), first, "fresh enough: not re-resolved");
  assert.equal(calls, 0);
  await refreshAllow(p, config, { now: 1000 + 5 * 60 * 1000 + 1, lookup: counting });
  assert.equal(calls, 2, "stale after five minutes");
  config.allowlist.homes = ["192.0.2.1"];
  assert.deepEqual((await refreshAllow(p, config, { now: 1000 + 5 * 60 * 1000 + 2, lookup: counting })).ips, ["192.0.2.1"], "a changed home list re-resolves at once");
  assert.equal(await refreshAllow(p, { allowlist: { enabled: false, homes: [] } }), null);
  delete process.env.A2A_ETC; delete process.env.A2A_VAR;
  fs.rmSync(root, { recursive: true, force: true });
});
