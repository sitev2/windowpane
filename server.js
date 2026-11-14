// Browser-in-a-browser: static UI + a rewriting proxy. No dependencies. Node 16+.
// Usage: node server.js            (listens on 127.0.0.1:8080)
//        HOST=0.0.0.0 PORT=3000 node server.js
const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = +process.env.PORT || 8080;
const PUBLIC = path.join(__dirname, 'public');
const PASSWORD = process.env.PASSWORD || '';
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || ''; // e.g. https://sitev2.github.io
if (!PASSWORD && !['127.0.0.1', 'localhost'].includes(HOST)) {
  console.error('Refusing to listen on a public address without a PASSWORD environment variable.');
  process.exit(1);
}
const SECRET = process.env.SECRET || crypto.createHash('sha256').update('windowpane:' + PASSWORD).digest('hex');
const TOKEN = crypto.createHmac('sha256', SECRET).update('ok').digest('hex');
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const fails = new Map(); // ip -> {n, t}
function authed(req) {
  if (!PASSWORD) return true;
  try {
    const k = new URL(req.url, 'http://x').searchParams.get('k');
    if (k && k.length === TOKEN.length && crypto.timingSafeEqual(Buffer.from(k), Buffer.from(TOKEN))) return true;
  } catch {}
  const m = /(?:^|;\s*)wp=([a-f0-9]+)/.exec(req.headers.cookie || '');
  return !!m && m[1].length === TOKEN.length && crypto.timingSafeEqual(Buffer.from(m[1]), Buffer.from(TOKEN));
}
function loginPage(msg) {
  return `<!DOCTYPE html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Windowpane</title>
<body style="font:17px system-ui;background:#1b1d22;color:#e8eaee;display:grid;place-items:center;height:100vh;margin:0">
<form method="post" action="/login" style="display:grid;gap:14px;width:min(320px,86vw)">
<h1 style="margin:0;font-weight:300;letter-spacing:.04em">Windowpane</h1>
<input name="password" type="password" placeholder="Password" autofocus autocomplete="current-password" style="font:inherit;padding:12px 16px;border-radius:12px;border:1px solid #383c47;background:#14161a;color:inherit">
<button style="font:inherit;padding:12px;border-radius:12px;border:0;background:#6aa9ff;color:#0b1220;font-weight:600">Open</button>
<div style="color:#ff8a8a;min-height:1.2em">${msg || ''}</div></form>`;
}
function handleLogin(req, res) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const f = fails.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - f.t > 600000) { f.n = 0; f.t = Date.now(); }
  const isApi = req.url === '/api/login';
  if (f.n >= 10) { res.writeHead(429, { 'content-type': isApi ? 'application/json' : 'text/html' }); return res.end(isApi ? '{"error":"Too many attempts. Try again in 10 minutes."}' : loginPage('Too many attempts. Try again in 10 minutes.')); }
  let body = '';
  req.on('data', (c) => { body += c; if (body.length > 4096) req.destroy(); });
  req.on('end', () => {
    let pw = '';
    try { pw = isApi ? String(JSON.parse(body || '{}').password || '') : (new URLSearchParams(body).get('password') || ''); } catch {}
    if (crypto.timingSafeEqual(sha(pw), sha(PASSWORD))) {
      if (isApi) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ token: TOKEN })); }
      const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
      res.writeHead(302, { location: '/', 'set-cookie': `wp=${TOKEN}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${secure}` });
      return res.end();
    }
    f.n++; fails.set(ip, f);
    res.writeHead(401, { 'content-type': isApi ? 'application/json' : 'text/html' });
    res.end(isApi ? '{"error":"Wrong password."}' : loginPage('Wrong password.'));
  });
}
const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

// Refuse to fetch private/loopback addresses (stops the proxy being used to reach your LAN).
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') ||
    (l.startsWith('::ffff:') && isPrivate(l.slice(7)));
}

const px = (u) => '/proxy?url=' + encodeURIComponent(u) + (PASSWORD ? '&k=' + TOKEN : '');
function abs(u, base) {
  try { return new URL(u, base).href; } catch { return null; }
}
function rewriteUrl(u, base) {
  const t = u.trim();
  if (!t || /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i.test(t)) return u;
  const a = abs(t, base);
  return a && /^https?:/i.test(a) ? px(a) : u;
}

function injected(realUrl) {
  return `<script>(function(){
var REAL=${JSON.stringify(realUrl)};var K=${JSON.stringify(PASSWORD ? '&k=' + TOKEN : '')};
function P(u){try{var a=new URL(u,REAL).href;return /^https?:/.test(a)?'/proxy?url='+encodeURIComponent(a)+K:u}catch(e){return u}}
var f=window.fetch;if(f)window.fetch=function(i,o){try{if(typeof i==='string')i=P(i);else if(i&&i.url)i=new Request(P(i.url),i)}catch(e){}return f.call(this,i,o)};
var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=P(String(u));return xo.apply(this,arguments)};
window.open=function(u){if(u)location.href=P(u);return null};
document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[href]');if(a&&a.target==='_blank')a.target='_self'},true);
function report(){parent.postMessage({type:'nav',url:REAL,title:document.title},'*')}
addEventListener('load',report);new MutationObserver(report).observe(document.head||document.documentElement,{childList:true,subtree:true});
})();</script>`;
}

function rewriteHtml(html, base) {
  html = html.replace(/<meta[^>]+http-equiv=["']?(content-security-policy|x-frame-options)["']?[^>]*>/gi, '');
  html = html.replace(/<base\b[^>]*>/gi, '');
  html = html.replace(/(\s(?:href|src|action|poster|data-src)\s*=\s*)(["'])([\s\S]*?)\2/gi,
    (m, pre, q, v) => pre + q + rewriteUrl(v, base) + q);
  html = html.replace(/(<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["'][^"']*url=)([^"']+)/gi,
    (m, pre, v) => pre + rewriteUrl(v, base));
  html = html.replace(/\ssrcset\s*=\s*(["'])([\s\S]*?)\1/gi, (m, q, v) =>
    ' srcset=' + q + v.split(',').map(s => { const [u, ...r] = s.trim().split(/\s+/); return [rewriteUrl(u, base), ...r].join(' '); }).join(', ') + q);
  html = html.replace(/\snonce=["'][^"']*["']|\sintegrity=["'][^"']*["']/gi, '');
  const tag = injected(base);
  return /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, (m) => m + tag) : tag + html;
}
function rewriteCss(css, base) {
  return css.replace(/url\(\s*(["']?)([^)"']+)\1\s*\)/gi, (m, q, v) => 'url(' + q + rewriteUrl(v, base) + q + ')')
    .replace(/@import\s+(["'])([^"']+)\1/gi, (m, q, v) => '@import ' + q + rewriteUrl(v, base) + q);
}

async function handleProxy(req, res, reqUrl, hops = 0) {
  const target = reqUrl.searchParams.get('url');
  const send = (code, msg) => { res.writeHead(code, { 'content-type': 'text/html; charset=utf-8' });
    res.end(`<body style="font:15px system-ui;padding:3rem;max-width:40rem;margin:auto"><h2>Could not load page</h2><p>${msg}</p>`); };
  let u;
  try { u = new URL(target); } catch { return send(400, 'That address is not valid.'); }
  if (!/^https?:$/.test(u.protocol)) return send(400, 'Only http and https addresses work.');
  try {
    const addrs = await dns.lookup(u.hostname, { all: true });
    if (addrs.some(a => isPrivate(a.address))) return send(403, 'Private network addresses are blocked.');
  } catch { return send(502, 'Could not find ' + u.hostname + '.'); }

  const lib = u.protocol === 'https:' ? https : http;
  const headers = { 'user-agent': UA, accept: req.headers.accept || '*/*', 'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    'accept-encoding': 'identity' };
  if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
  if (req.headers['content-length']) headers['content-length'] = req.headers['content-length'];
  if (req.headers.range) headers.range = req.headers.range;

  const up = lib.request(u, { method: req.method, headers, timeout: 20000 }, (r) => {
    const h = { ...r.headers };
    ['x-frame-options', 'content-security-policy', 'content-security-policy-report-only', 'strict-transport-security',
      'content-encoding', 'content-length', 'set-cookie', 'referrer-policy', 'cross-origin-opener-policy', 'cross-origin-embedder-policy'].forEach(k => delete h[k]);
    h['referrer-policy'] = 'no-referrer';
    if (h.location) {
      const l = abs(h.location, u.href);
      if (l) h.location = px(l);
    }
    const ct = (r.headers['content-type'] || '').toLowerCase();
    if (ct.includes('text/html') || ct.includes('text/css')) {
      const chunks = [];
      r.on('data', c => chunks.push(c));
      r.on('end', () => {
        let body = Buffer.concat(chunks).toString('utf8');
        body = ct.includes('text/html') ? rewriteHtml(body, u.href) : rewriteCss(body, u.href);
        h['content-type'] = ct.includes('text/html') ? 'text/html; charset=utf-8' : 'text/css; charset=utf-8';
        res.writeHead(r.statusCode, h);
        res.end(body);
      });
    } else {
      res.writeHead(r.statusCode, h);
      r.pipe(res);
    }
  });
  up.on('timeout', () => up.destroy(new Error('timeout')));
  up.on('error', (e) => { if (!res.headersSent) send(502, 'The site did not respond (' + e.message + ').'); else res.end(); });
  req.pipe(up);
}

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
http.createServer((req, res) => {
  const reqUrl = new URL(req.url, 'http://x');
  if (req.url === '/healthz') { res.writeHead(200); return res.end('ok'); }
  if (reqUrl.pathname === '/api/login') {
    if (ALLOW_ORIGIN && req.headers.origin === ALLOW_ORIGIN) {
      res.setHeader('access-control-allow-origin', ALLOW_ORIGIN);
      res.setHeader('access-control-allow-headers', 'content-type');
      res.setHeader('vary', 'origin');
    }
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    if (PASSWORD && req.method === 'POST') return handleLogin(req, res);
    res.writeHead(404); return res.end();
  }
  if (PASSWORD && reqUrl.pathname === '/login' && req.method === 'POST') return handleLogin(req, res);
  if (!authed(req)) { res.writeHead(401, { 'content-type': 'text/html' }); return res.end(loginPage()); }
  if (reqUrl.pathname === '/proxy') return handleProxy(req, res, reqUrl);
  const file = path.join(PUBLIC, reqUrl.pathname === '/' ? 'index.html' : path.normalize(reqUrl.pathname));
  if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (e, d) => {
    if (e) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(d);
  });
}).listen(PORT, HOST, () => console.log(`Browser running at http://${HOST}:${PORT}`));
