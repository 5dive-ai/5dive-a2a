// The web-server edits setup makes, on the shapes they meet: the managed-box
// Caddyfile (5dive-api scripts/install/services.sh) and an nginx site with an
// :80 redirect block ahead of the 443 block.
import test from "node:test";
import assert from "node:assert/strict";
import { caddyInsert, caddyRemove, nginxInsert } from "../a2a/lib/cli.mjs";

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

test("caddy: the route goes in before the catch-all, once, and comes out clean", () => {
  const r = caddyInsert(CADDY, 7461);
  assert.equal(r.changed, true);
  const i = r.text.indexOf("handle /openagent/inbox"), j = r.text.indexOf("    handle {");
  assert.ok(i > 0 && i < j, "inside the site block, before the catch-all");
  assert.match(r.text, /reverse_proxy 127\.0\.0\.1:7461/);
  assert.equal(caddyInsert(r.text, 7461).changed, false, "idempotent");
  assert.equal(caddyRemove(r.text), CADDY);
});

test("caddy: no catch-all means no edit, and a reason", () => {
  const r = caddyInsert("box.example.com {\n    respond 200\n}\n", 7461);
  assert.equal(r.changed, false);
  assert.match(r.reason, /catch-all/);
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
