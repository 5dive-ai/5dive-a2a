// The web-server edits setup makes, on the shapes they meet: the managed-box
// Caddyfile (5dive-api scripts/install/services.sh), teal-fox's Caddyfile (a
// snippet with a catch-all, imported by other sites, ahead of the box's own site),
// and an nginx site with an :80 redirect block ahead of the 443 block.
import test from "node:test";
import assert from "node:assert/strict";
import { caddyInsert, caddyRemove, caddyBlocks, nginxInsert, nginxSnippet, NGINX_ZONE_TEXT, INBOX_SOCKET } from "../a2a/lib/cli.mjs";

const CADDY = `{
    email ops@example.com
}

box.example.com {
    log {
        format json
    }
    handle /shell/* {
        reverse_proxy localhost:3101
    }
    handle /files/* {
        reverse_proxy localhost:3101
    }
    handle {
        reverse_proxy localhost:3000
    }
}
`;

// teal-fox, 2026-09-27: the first `handle {` in the file is inside (cf_www), which five
// other vhosts import. The box's own site comes after it.
const TEAL = `{
\temail ops@example.com
}

(cf_www) {
\ttls {
\t\tdns cloudflare {env.CF_API_TOKEN}
\t}
\thandle {
\t\treverse_proxy localhost:8080
\t}
}

one.example.org, www.one.example.org {
\timport cf_www
}

two.example.org {
\timport cf_www
}

teal-fox.example.com {
\ttls {
\t\tdns cloudflare {env.CF_API_TOKEN}
\t}
\thandle /shell/* {
\t\treverse_proxy localhost:3101
\t}
\thandle {
\t\treverse_proxy localhost:3000
\t}
}
`;

const blockOf = (text, at) => caddyBlocks(text.split("\n")).find((b) => b.start < at && at < b.end);
const lineOf = (text, needle) => text.split("\n").findIndex((l) => l.includes(needle));

test("caddy: the route goes in before the catch-all, once, and comes out clean", () => {
  const r = caddyInsert(CADDY, "box.example.com");
  assert.equal(r.changed, true);
  const i = r.text.indexOf("handle /openagent/inbox"), j = r.text.indexOf("    handle {");
  assert.ok(i > 0 && i < j, "inside the site block, before the catch-all");
  assert.match(r.text, new RegExp(`reverse_proxy unix/${INBOX_SOCKET.replace(/\./g, "\\.")}`));
  assert.doesNotMatch(r.text, /127\.0\.0\.1/, "no TCP upstream: the inbox has no network");
  assert.match(r.text, /max_size 64KiB/, "Caddy has no rate limit; the body is capped");
  assert.equal(caddyInsert(r.text, "box.example.com").changed, false, "idempotent");
  assert.equal(caddyRemove(r.text), CADDY);
});

test("caddy: a snippet ahead of the site never gets the route (teal-fox)", () => {
  const r = caddyInsert(TEAL, "teal-fox.example.com");
  assert.equal(r.changed, true);
  const at = lineOf(r.text, "# 5dive-a2a:begin");
  const b = blockOf(r.text, at);
  assert.deepEqual(b.addresses, ["teal-fox.example.com"], "inside the teal-fox site block");
  assert.ok(at < lineOf(r.text.split("\n").slice(b.start).join("\n"), "\thandle {") + b.start, "before its catch-all");
  const snippet = caddyBlocks(r.text.split("\n")).find((x) => x.snippet);
  assert.ok(!r.text.split("\n").slice(snippet.start, snippet.end).some((l) => l.includes("openagent")), "the (cf_www) snippet is untouched");
  assert.match(r.text, /\n\t# 5dive-a2a:begin\n\thandle \/openagent\/inbox \{\n\t\trequest_body/, "follows the file's tab indent");
  assert.equal(caddyRemove(r.text), TEAL);
});

test("caddy: no site block for the domain means no edit, and a reason", () => {
  for (const d of ["other.example.com", "example.com", "cf_www"]) {
    const r = caddyInsert(TEAL, d);
    assert.equal(r.changed, false, d);
    assert.match(r.reason, /no site block/);
  }
  const r = caddyInsert(TEAL, "www.one.example.org");
  assert.equal(r.changed, true, "a second address on the header line is still that site");
});

test("caddy: two blocks for the domain is a refusal, not a guess", () => {
  const r = caddyInsert(CADDY + "\nhttps://box.example.com:443 {\n    respond 200\n}\n", "box.example.com");
  assert.equal(r.changed, false);
  assert.match(r.reason, /2 site blocks/);
  const http = caddyInsert(CADDY + "\nhttp://box.example.com {\n    redir https://{host}{uri}\n}\n", "box.example.com");
  assert.equal(http.changed, true, "an http:// redirect block is not a second site");
  assert.ok(blockOf(http.text, lineOf(http.text, "# 5dive-a2a:begin")).addresses[0] === "box.example.com");
});

test("caddy: no catch-all means the route goes before the site's closing brace", () => {
  const r = caddyInsert("box.example.com {\n    respond 200\n}\n", "box.example.com");
  assert.equal(r.changed, true);
  const lines = r.text.split("\n");
  assert.equal(lines[1], "    respond 200");
  assert.equal(lines[2], "    # 5dive-a2a:begin");
  assert.equal(lines.at(-2), "}");
});

test("caddy: luca's hand fix (markers moved into the site, TCP upstream) is upgraded in place", () => {
  const hand = caddyInsert(TEAL, "teal-fox.example.com").text
    .replace(/reverse_proxy unix\/\S+/g, "reverse_proxy 127.0.0.1:7461").replace(/\t\trequest_body \{\n\t\t\tmax_size 64KiB\n\t\t\}\n/, "");
  const r = caddyInsert(hand, "teal-fox.example.com");
  assert.equal(r.changed, true);
  assert.equal(r.moved, undefined, "the markers stay where they are");
  assert.equal(r.text.split("# 5dive-a2a:begin").length, 2, "one block, not two");
  assert.equal(r.text, caddyInsert(TEAL, "teal-fox.example.com").text);
});

test("caddy: markers left inside a snippet by the old setup are moved to the site", () => {
  const lines = TEAL.split("\n");
  const at = lines.findIndex((l) => l === "\thandle {");
  lines.splice(at, 0, "    # 5dive-a2a:begin", "    handle /openagent/inbox {", "        reverse_proxy 127.0.0.1:7461", "    }", "    # 5dive-a2a:end");
  const r = caddyInsert(lines.join("\n"), "teal-fox.example.com");
  assert.equal(r.changed, true);
  assert.equal(r.moved, true);
  assert.equal(r.text.split("# 5dive-a2a:begin").length, 2);
  assert.deepEqual(blockOf(r.text, lineOf(r.text, "# 5dive-a2a:begin")).addresses, ["teal-fox.example.com"]);
  assert.equal(caddyRemove(r.text), TEAL);
});

test("caddy: {env.X} placeholders and comments do not move the block depth", () => {
  const blocks = caddyBlocks(TEAL.replace("(cf_www) {", "(cf_www) { # the { shared } one").split("\n"));
  assert.deepEqual(blocks.map((b) => b.head), ["", "(cf_www)", "one.example.org, www.one.example.org", "two.example.org", "teal-fox.example.com"]);
});

const NGINX = `server {
    listen 80;
    server_name api.example.com;
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.example.com;
    location / { proxy_pass http://127.0.0.1:3001; }
}
`;

test("nginx: the include lands in the 443 block, not the :80 redirect", () => {
  const r = nginxInsert(NGINX, "api.example.com");
  assert.equal(r.changed, true);
  const lines = r.text.split("\n");
  const at = lines.findIndex((l) => l.includes("include /etc/nginx/snippets/5dive-a2a.conf;"));
  assert.ok(at > lines.findIndex((l) => l.includes("listen 443")), "after listen 443");
  assert.equal(nginxInsert(r.text, "api.example.com").changed, false, "idempotent");
  assert.equal(nginxInsert(NGINX, "other.example.com").changed, false);
});

test("nginx: the snippet proxies to the unix socket and rate-limits before node", () => {
  const s = nginxSnippet(true);
  assert.equal((s.match(new RegExp(`proxy_pass http://unix:${INBOX_SOCKET.replace(/\./g, "\\.")}:;`, "g")) || []).length, 2);
  assert.doesNotMatch(s, /127\.0\.0\.1/);
  assert.equal((s.match(/limit_req zone=fivedive_a2a /g) || []).length, 2);
  assert.match(NGINX_ZONE_TEXT, /^limit_req_zone \$binary_remote_addr zone=fivedive_a2a:1m rate=60r\/m;$/m);
  assert.doesNotMatch(nginxSnippet(false), /limit_req/, "no zone loaded, no reference to it (nginx -t would fail)");
});
