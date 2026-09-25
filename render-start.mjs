import http from 'node:http';
import net from 'node:net';
import zlib from 'node:zlib';
import { spawn } from 'node:child_process';

// One public listener routes the upstream master and one game worker.
const child = spawn(process.execPath, ['--import', 'tsx', 'src/server/Server.ts'], {
  stdio: 'inherit',
  env: { ...process.env, GAME_ENV: 'dev', DOMAIN: 'localhost', NUM_WORKERS: '1',
    INSTANCE_LETTER: 'a', GIT_COMMIT: '38cd12d4043ce6e700fc31da29dd1be39dc67879',
    TURNSTILE_SITE_KEY: '1x00000000000000000000AA', ADMIN_BOT_API_KEY: '',
    SUBDOMAIN: '', GAME_HOST: '', SITE_HOST: '', LOBBY_COORDINATOR: 'off' },
});

function route(url = '/') {
  if (/^\/w0(?:\/|\?|$)/.test(url)) return { port: 3001, path: url.replace(/^\/w0/, '') || '/' };
  if (/^\/api\/create_game(?:\?|$)/.test(url)) return { port: 3001, path: url };
  return { port: 3000, path: url };
}

const PUBLIC_ORIGIN = 'https://openfront-friends.onrender.com';

// ---------------------------------------------------------------------------
// Self-host API stubs.
//
// The web client expects the OpenFront API service (api.openfront.io in prod,
// localhost:8787 in dev) for its server-list heartbeat, news, cosmetics, etc.
// That service is not part of this deployment, so answer the endpoints the
// client needs right here. Any HTTP status below 500 counts as "reachable";
// /cluster.json 404 means "reachable, no list" and the client falls back to
// the cluster map injected into the page.
// ---------------------------------------------------------------------------
function apiStub(req, res) {
  const path = (req.url || '/').split('?')[0];
  const json = (code, obj) => {
    const body = Buffer.from(JSON.stringify(obj));
    res.writeHead(code, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': body.length,
      'cache-control': 'no-store',
    });
    res.end(body);
  };
  const stubs = {
    '/cluster.json': [404, { error: 'site not registered' }],
    '/news.json': [404, { error: 'not found' }],
    '/cosmetics.json': [200, []],
    '/reserved_clan_tags': [200, []],
    '/marketing/consent': [200, {}],
    '/users/@me': [401, { error: 'no session' }],
  };
  const hit = stubs[path];
  if (!hit) return false;
  json(hit[0], hit[1]);
  return true;
}

// ---------------------------------------------------------------------------
// Page patching.
//
// Two fixes applied to every HTML page served by the game server:
//
// 1. Point the client at this server for its API calls.
//    Also hide the client-rendered "Buy OpenFront on Steam" wishlist banner
//    (no ad/promo units are served on this self-host). The client reads
//    localStorage "apiHost" (its documented dev override) before falling back
//    to the unreachable localhost:8787. Without this the menu shows
//    "Can't connect to the OpenFront servers" and lobby buttons stay blocked.
// 2. Remove the third-party Playwire ad tag. Ads are not required on a
//    self-host; the tag belongs to the official site's ad account.
// ---------------------------------------------------------------------------
const APIHOST_SCRIPT =
  `<script>try{localStorage.setItem("apiHost","${PUBLIC_ORIGIN}")}catch(e){}</script>` +
  `<style>.steam-wishlist-frame{display:none!important}</style>`;
const RAMP_TAG_RE = /<script[^>]*cdn\.intergient\.com[^>]*>\s*<\/script>/gi;

function patchHtml(html) {
  let out = html.replace(/<head[^>]*>/i, (m) => m + APIHOST_SCRIPT);
  if (out === html) out = APIHOST_SCRIPT + html; // no <head>: prepend
  out = out.replace(RAMP_TAG_RE, '<!-- ads disabled on this self-host -->');
  return out;
}

function looksLikePage(url) {
  const path = (url || '/').split('?')[0];
  if (path === '/') return true;
  const last = path.split('/').pop() || '';
  return !last.includes('.');
}

const front = http.createServer((req, res) => {
  if (apiStub(req, res) !== false) return;

  const target = route(req.url);
  const pagePatch = req.method === 'GET' && looksLikePage(req.url);
  const headers = { ...req.headers };
  if (pagePatch) {
    // We rewrite the HTML, so ask upstream for an uncompressed, fresh copy.
    delete headers['accept-encoding'];
    delete headers['if-none-match'];
    delete headers['if-modified-since'];
  }
  const upstream = http.request({ hostname: '127.0.0.1', ...target,
    method: req.method, headers }, (response) => {
    const ctype = String(response.headers['content-type'] || '');
    if (pagePatch && ctype.includes('text/html')) {
      const chunks = [];
      response.on('data', (c) => chunks.push(c));
      response.on('end', () => {
        try {
          let body = Buffer.concat(chunks);
          const enc = String(response.headers['content-encoding'] || '').toLowerCase();
          if (enc.includes('gzip')) body = zlib.gunzipSync(body);
          else if (enc.includes('deflate')) body = zlib.inflateSync(body);
          else if (enc.includes('br')) body = zlib.brotliDecompressSync(body);
          const patched = Buffer.from(patchHtml(body.toString('utf8')));
          const outHeaders = { ...response.headers };
          delete outHeaders['content-length'];
          delete outHeaders['content-encoding'];
          delete outHeaders['etag'];
          delete outHeaders['last-modified'];
          res.writeHead(response.statusCode ?? 502, outHeaders);
          res.end(patched);
        } catch {
          res.writeHead(502);
          res.end('Page render failed. Please try again.');
        }
      });
      response.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
      return;
    }
    res.writeHead(response.statusCode ?? 502, response.headers);
    response.pipe(res);
  });
  upstream.on('error', () => { if (!res.headersSent) res.writeHead(503); res.end('Server is starting. Please try again.'); });
  res.on('close', () => upstream.destroy());
  req.pipe(upstream);
});
front.on('upgrade', (req, socket, head) => {
  const target = route(req.url);
  const upstream = net.connect(target.port, '127.0.0.1', () => {
    const headers = [];
    for (let i = 0; i < req.rawHeaders.length; i += 2) headers.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
    upstream.write(`${req.method} ${target.path} HTTP/${req.httpVersion}\r\n${headers.join('\r\n')}\r\n\r\n`);
    if (head.length) upstream.write(head);
    socket.pipe(upstream).pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => upstream.destroy());
  socket.on('close', () => upstream.destroy());
});
front.listen(Number(process.env.PORT || 10000), '0.0.0.0');
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { child.kill(signal); front.close(); });
child.on('exit', code => { front.close(); process.exit(code ?? 1); });
