// Integration test: boots render-start.mjs (proxy + master + worker) with
// POCKET_EDU_AUTH_* pointing at a local stub JWKS, then exercises:
//  - /users/@me with no/invalid/valid tokens
//  - authenticated REST (create_game) with a Pocket Edu token
//  - guest create_game still works
//  - exact-origin CORS grants + preflights
//  - server starts and serves guests when the JWKS endpoint is unreachable
import { spawn } from "node:child_process";
import http from "node:http";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { randomUUID } from "node:crypto";

const ISSUER = "https://pocketedu.test";
const AUDIENCE = "pocketedu-openfront-test";
const JWKS_PORT = 19999;
const JWKS_URL = `http://127.0.0.1:${JWKS_PORT}/.well-known/openfront-jwks.json`;
const APP_PORT = 18080;
const BASE = `http://127.0.0.1:${APP_PORT}`;
const KID = "integ-key-1";
const ACCOUNT_UUID = "123e4567-e89b-12d3-a456-426614174000";

function uuidToBase64url(uuid) {
  const bytes = Buffer.from(uuid.replace(/-/g, ""), "hex");
  return bytes.toString("base64url");
}

let failures = 0;
function check(name, cond, extra = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra && cond ? "" : " " + extra}`);
  if (!cond) failures++;
}

function req(method, path, { headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(path, BASE);
    const r = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString() }),
        );
      },
    );
    r.on("error", reject);
    if (body) r.write(body);
    r.end();
  });
}

async function makeToken(key, opts = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: opts.iss ?? ISSUER,
    aud: opts.aud ?? AUDIENCE,
    sub: uuidToBase64url(ACCOUNT_UUID),
    provider: "pocketedu",
    name: "Integ Player",
    jti: randomUUID(),
    iat: now,
    exp: now + 120,
  })
    .setProtectedHeader({ alg: "EdDSA", kid: KID })
    .sign(key);
}

function startJwksServer(jwks) {
  return http
    .createServer((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(jwks));
    })
    .listen(JWKS_PORT, "127.0.0.1");
}

function startApp(extraEnv = {}) {
  const child = spawn(process.execPath, ["render-start.mjs"], {
    cwd: new URL(".", import.meta.url).pathname,
    env: {
      ...process.env,
      PORT: String(APP_PORT),
      POCKET_EDU_AUTH_ISSUER: ISSUER,
      POCKET_EDU_AUTH_AUDIENCE: AUDIENCE,
      POCKET_EDU_AUTH_JWKS_URL: JWKS_URL,
      ...extraEnv,
    },
    stdio: "pipe",
  });
  child.stderr.on("data", () => {});
  child.stdout.on("data", () => {});
  return child;
}

async function waitForApp(child, timeoutMs = 120000) {
  const start = Date.now();
  for (;;) {
    try {
      // /api/health is served by the upstream master (not a proxy stub),
      // so a non-503 answer proves the game server itself is up.
      const r = await req("GET", "/api/health");
      if (r.status !== 503) return true;
    } catch {}
    if (Date.now() - start > timeoutMs) return false;
    await new Promise((r) => setTimeout(r, 1000));
  }
}

function kill(child) {
  return new Promise((resolve) => {
    child.on("exit", resolve);
    child.kill("SIGTERM");
    setTimeout(() => { try { child.kill("SIGKILL"); } catch {} resolve(); }, 5000);
  });
}

const { publicKey, privateKey } = await generateKeyPair("EdDSA");
const jwk = await exportJWK(publicKey);
jwk.kid = KID;
jwk.alg = "EdDSA";

// ---- Phase 1: JWKS reachable ----
const jwksServer = startJwksServer({ keys: [jwk] });
const app = startApp();
check("app boots with JWKS available", await waitForApp(app));

const validToken = await makeToken(privateKey);

let r = await req("GET", "/users/@me");
check("GET /users/@me without token -> 401 no session", r.status === 401 && r.text.includes("no session"), `got ${r.status} ${r.text}`);

r = await req("GET", "/users/@me", { headers: { authorization: `Bearer ${validToken}` } });
let profile = null;
try { profile = JSON.parse(r.text); } catch {}
check("GET /users/@me with valid token -> 200", r.status === 200, `got ${r.status} ${r.text}`);
check("profile has signed display name, no entitlements",
  profile?.player?.username === "Integ Player" &&
  profile?.player?.adfree === false &&
  profile?.player?.subscription === null &&
  Array.isArray(profile?.player?.friends) &&
  typeof profile?.player?.publicId === "string" &&
  profile?.player?.publicId !== ACCOUNT_UUID,
  r.text.slice(0, 200));
check("profile response is no-store", String(r.headers["cache-control"] || "").includes("no-store"), String(r.headers["cache-control"]));

const tampered = validToken.slice(0, -2) + "xx";
r = await req("GET", "/users/@me", { headers: { authorization: `Bearer ${tampered}` } });
check("GET /users/@me with tampered token -> 401 (fail closed, not guest)", r.status === 401 && r.text.includes("invalid session"), `got ${r.status} ${r.text}`);

r = await req("POST", "/w0/api/create_game", {
  headers: { authorization: `Bearer ${validToken}`, "content-type": "application/json" },
  body: JSON.stringify({}),
});
let gameId = null;
try { gameId = JSON.parse(r.text)?.gameID; } catch {}
check("POST create_game with Pocket Edu token -> 200 + gameID", r.status === 200 && typeof gameId === "string", `got ${r.status} ${r.text.slice(0, 160)}`);

const guestUuid = randomUUID();
r = await req("POST", "/w0/api/create_game", {
  headers: { authorization: `Bearer ${guestUuid}`, "content-type": "application/json" },
  body: JSON.stringify({}),
});
check("POST create_game as guest still works", r.status === 200, `got ${r.status} ${r.text.slice(0, 160)}`);

// ---- Lobby ownership: raw subject UUID / publicId must not reclaim it ----
// gameId is the account's lobby. Attackers presenting the account's raw
// subject UUID or its public profile id as guest tokens must fail the
// creator check (403); the real account (fresh token) must pass (200).
const attackerBody = JSON.stringify({});
r = await req("POST", `/w0/api/create_game?previous=${gameId}`, {
  headers: { authorization: `Bearer ${ACCOUNT_UUID}`, "content-type": "application/json" },
  body: attackerBody,
});
check("guest with account's raw subject UUID cannot spawn successor lobby (403)",
  r.status === 403 && r.text.includes("Only the lobby creator"), `got ${r.status} ${r.text.slice(0, 160)}`);

r = await req("POST", `/w0/api/create_game?previous=${gameId}`, {
  headers: { authorization: `Bearer ${profile?.player?.publicId}`, "content-type": "application/json" },
  body: attackerBody,
});
check("guest with account's publicId cannot spawn successor lobby (403)",
  r.status === 403 && r.text.includes("Only the lobby creator"), `got ${r.status} ${r.text.slice(0, 160)}`);

const freshToken = await makeToken(privateKey);
r = await req("POST", `/w0/api/create_game?previous=${gameId}`, {
  headers: { authorization: `Bearer ${freshToken}`, "content-type": "application/json" },
  body: attackerBody,
});
check("account (fresh token) can spawn successor lobby for its own game (200)",
  r.status === 200, `got ${r.status} ${r.text.slice(0, 160)}`);

const publicIdBeforeRestart = profile?.player?.publicId;
check("publicId matches fixed cross-process vector",
  publicIdBeforeRestart === "5faf33e7-0919-59b8-a99b-05c41e8113b5", String(publicIdBeforeRestart));

// ---- CORS ----
const NETLIFY_ORIGIN = "https://pocket-edu-openfront.netlify.app";
r = await req("GET", "/users/@me", { headers: { origin: NETLIFY_ORIGIN } });
check("exact Netlify origin gets CORS grant", r.headers["access-control-allow-origin"] === NETLIFY_ORIGIN, String(r.headers["access-control-allow-origin"]));
check("Vary: Origin present", String(r.headers["vary"] || "").includes("Origin"));

r = await req("GET", "/users/@me", { headers: { origin: "https://evil.test" } });
check("unlisted origin gets no CORS grant", !("access-control-allow-origin" in r.headers));

r = await req("OPTIONS", "/users/@me", {
  headers: { origin: NETLIFY_ORIGIN, "access-control-request-method": "GET", "access-control-request-headers": "authorization" },
});
check("preflight for allowed origin -> 204 with grants",
  r.status === 204 && r.headers["access-control-allow-origin"] === NETLIFY_ORIGIN &&
  String(r.headers["access-control-allow-headers"] || "").includes("Authorization"),
  `got ${r.status}`);

r = await req("OPTIONS", "/users/@me", { headers: { origin: "https://evil.test" } });
check("preflight for unlisted origin -> no grant", !("access-control-allow-origin" in r.headers));

await kill(app);

// ---- Phase 1b: restart with JWKS still up — identity must be stable ----
// A brand-new server process (new boot, new module state) must derive the
// same identity for the same account, even for a freshly-issued token.
const appRestart = startApp();
check("app reboots with JWKS available", await waitForApp(appRestart));

const restartToken = await makeToken(privateKey);
r = await req("GET", "/users/@me", { headers: { authorization: `Bearer ${restartToken}` } });
let profileAfter = null;
try { profileAfter = JSON.parse(r.text); } catch {}
check("same account after restart -> 200", r.status === 200, `got ${r.status} ${r.text.slice(0, 120)}`);
check("publicId identical across restart (stable cross-process identity)",
  profileAfter?.player?.publicId === publicIdBeforeRestart,
  `before=${publicIdBeforeRestart} after=${profileAfter?.player?.publicId}`);

r = await req("POST", "/w0/api/create_game", {
  headers: { authorization: `Bearer ${restartToken}`, "content-type": "application/json" },
  body: JSON.stringify({}),
});
check("account create_game works after restart", r.status === 200, `got ${r.status} ${r.text.slice(0, 120)}`);

await kill(appRestart);

// ---- Phase 2: JWKS unreachable — server must still start and serve guests ----
await new Promise((resolve) => jwksServer.close(resolve));
const app2 = startApp({ POCKET_EDU_AUTH_JWKS_URL: "http://127.0.0.1:19998/nonexistent" });
check("app boots with JWKS unreachable", await waitForApp(app2));

r = await req("POST", "/w0/api/create_game", {
  headers: { authorization: `Bearer ${randomUUID()}`, "content-type": "application/json" },
  body: JSON.stringify({}),
});
check("guest create_game works with JWKS down", r.status === 200, `got ${r.status}`);

r = await req("GET", "/users/@me", { headers: { authorization: `Bearer ${validToken}` } });
check("account /users/@me fails closed (401) with JWKS down", r.status === 401, `got ${r.status} ${r.text.slice(0, 120)}`);

r = await req("GET", "/users/@me");
check("guest /users/@me still 401 no session with JWKS down", r.status === 401 && r.text.includes("no session"));

await kill(app2);

console.log(failures === 0 ? "\nALL INTEGRATION CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
