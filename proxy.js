// proxy.js - Render production proxy (fixed CORS + static routing)

const express = require('express');
const https = require('https');
const { URL } = require('url');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();

// --- Configuration via environment variables ---
const PORT = process.env.PORT || 4000;
const ALLOW_LEGACY_TLS = (process.env.ALLOW_LEGACY_TLS || 'true') === 'true';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const CHIBAN_APPID = process.env.CHIBAN_APPID || '';
const H_CHIBAN_APPID = process.env.H_CHIBAN_APPID || '';
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '120', 10);

// --- Simple in-memory rate limiter ---
const rateMap = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const rec = rateMap.get(ip) || { ts: now, count: 0 };
  if (now - rec.ts > RATE_LIMIT_WINDOW_MS) {
    rec.ts = now;
    rec.count = 1;
  } else {
    rec.count += 1;
  }
  rateMap.set(ip, rec);
  return rec.count <= RATE_LIMIT_MAX;
}

// --- Legacy TLS agent ---
let agent;
if (ALLOW_LEGACY_TLS) {
  try {
    agent = new https.Agent({
      secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT
    });
    console.log('proxy: ALLOW_LEGACY_TLS enabled');
  } catch (e) {
    agent = new https.Agent();
    console.warn('proxy: legacy TLS not available; continuing');
  }
} else {
  agent = new https.Agent();
  console.log('proxy: ALLOW_LEGACY_TLS disabled');
}

/// --- CORS / Origin check ---
// 通常のページ表示（Origin なし）は許可する
app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  const referer = req.headers.referer || '';

  // Origin も Referer も無い → ブラウザの通常アクセス → 許可
  if (!origin && !referer) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    if (req.method === 'OPTIONS') return res.status(204).end();
    return next();
  }

  // ここから先は API 呼び出しなど Origin がある場合
  const effectiveOrigin = origin || referer;

  if (ALLOWED_ORIGINS.length > 0) {
    const ok = ALLOWED_ORIGINS.some(o => effectiveOrigin.startsWith(o));
    if (!ok) {
      res.setHeader('Access-Control-Allow-Origin', 'null');
      return res.status(403).send('Origin not allowed');
    }
    res.setHeader('Access-Control-Allow-Origin', effectiveOrigin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// --- Logging ---
app.use((req, res, next) => {
  console.log(
    `[incoming] ${req.method} ${req.originalUrl} ip:${req.ip} origin:${req.headers.origin || '-'} referer:${req.headers.referer || '-'}`
  );
  next();
});

// --- Health check ---
app.get('/__health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// --- Proxy helper ---
function proxyRequestToTarget(req, res, targetUrl, options = {}) {
  try {
    const parsed = new URL(targetUrl);
    const opts = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: req.method || 'GET',
      headers: Object.assign({}, req.headers, options.overrideHeaders || {}),
      timeout: options.timeout || 15000,
      agent: agent
    };

    delete opts.headers['host'];
    delete opts.headers['connection'];
    delete opts.headers['keep-alive'];
    delete opts.headers['transfer-encoding'];
    delete opts.headers['upgrade'];
    delete opts.headers['proxy-authorization'];
    delete opts.headers['proxy-authenticate'];

    if (!opts.headers['accept']) opts.headers['accept'] = 'application/json';

    const proxyReq = https.request(opts, (proxyRes) => {
      res.statusCode = proxyRes.statusCode || 502;
      Object.keys(proxyRes.headers || {}).forEach(k => {
        if (!['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailers','transfer-encoding','upgrade'].includes(k.toLowerCase())) {
          res.setHeader(k, proxyRes.headers[k]);
        }
      });
      if (!res.getHeader('Access-Control-Allow-Origin')) {
        res.setHeader('Access-Control-Allow-Origin', '*');
      }
      proxyRes.pipe(res);
    });

    proxyReq.on('timeout', () => {
      console.error('[proxy timeout]', targetUrl);
      proxyReq.destroy();
      if (!res.headersSent) res.status(504).send('Gateway Timeout');
    });

    proxyReq.on('error', (err) => {
      console.error('[proxy error]', targetUrl, err);
      if (!res.headersSent) res.status(502).json({ error: 'Proxy request failed' });
    });

    if (['POST','PUT','PATCH'].includes((req.method || '').toUpperCase())) {
      req.pipe(proxyReq);
    } else {
      proxyReq.end();
    }
  } catch (err) {
    console.error('[proxy exception]', err);
    if (!res.headersSent) res.status(500).send('Internal Server Error');
  }
}

// --- Normalize endpoint ---
function normalizeEndpointPath(basePath) {
  let p = basePath || '';
  if (p.startsWith('/')) p = p.slice(1);
  p = p.replace(/^api-chiban\/?/, 'api/');
  p = p.replace(/^chiban\/?/, 'api/');
  p = p.replace(/^api-h-chiban\/?/, 'api/');
  p = p.replace(/^houmu\/?/, 'api/');
  if (!p.startsWith('api/')) p = 'api/' + p;
  return p;
}

// --- Chiban handler ---
function chibanHandler(req, res) {
  const ip = req.ip || 'unknown';
  if (!checkRateLimit(ip)) return res.status(429).send('Too Many Requests');

  const endpointPath = normalizeEndpointPath(req.path);
  const query = req.url.includes('?') ? req.url.split('?')[1] : '';
  const params = new URLSearchParams(query || '');
  if (!params.has('appid') && CHIBAN_APPID) params.set('appid', CHIBAN_APPID);

  const targetUrl = `https://api-chiban.geospace.jp/${endpointPath}${params.toString() ? '?' + params.toString() : ''}`;
  console.log('[proxy] chiban ->', targetUrl);
  proxyRequestToTarget(req, res, targetUrl);
}

// --- Houmu handler ---
function houmuHandler(req, res) {
  const ip = req.ip || 'unknown';
  if (!checkRateLimit(ip)) return res.status(429).send('Too Many Requests');

  const endpointPath = normalizeEndpointPath(req.path);
  const query = req.url.includes('?') ? req.url.split('?')[1] : '';
  const params = new URLSearchParams(query || '');
  if (!params.has('appid') && H_CHIBAN_APPID) params.set('appid', H_CHIBAN_APPID);

  const targetUrl = `https://api-h-chiban.geospace.jp/${endpointPath}${params.toString() ? '?' + params.toString() : ''}`;
  console.log('[proxy] houmu ->', targetUrl);
  proxyRequestToTarget(req, res, targetUrl);
}

// --- Mount handlers ---
app.use('/chiban', chibanHandler);
app.use('/api-chiban', chibanHandler);
app.use('/houmu', houmuHandler);
app.use('/api-h-chiban', houmuHandler);

// --- Static assets (Experience Builder build output) ---
const EXB_CLIENT_DIST = process.env.EXB_CLIENT_DIST || './';
const resolvedDist = path.isAbsolute(EXB_CLIENT_DIST)
  ? EXB_CLIENT_DIST
  : path.join(__dirname, EXB_CLIENT_DIST);

console.log('proxy: serving ExB client dist from', resolvedDist);

// dist 全体を静的配信
app.use(express.static(resolvedDist, {
  maxAge: '1d',
  index: false
}));

// ルートは index.html
app.get('/', (req, res) => {
  const indexPath = path.join(resolvedDist, 'index.html');
  if (!fs.existsSync(indexPath)) {
    console.error('sendFile / index.html not found at', indexPath);
    return res.status(404).send('Not Found');
  }
  res.sendFile(indexPath);
});

// SPA fallback
app.get('*', (req, res) => {
  const indexPath = path.join(resolvedDist, 'index.html');
  if (!fs.existsSync(indexPath)) {
    return res.status(404).send('Not Found');
  }
  res.sendFile(indexPath);
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Proxy server listening on port ${PORT}`);
  console.log(`ALLOW_LEGACY_TLS=${ALLOW_LEGACY_TLS} CHIBAN_APPID=${!!CHIBAN_APPID} H_CHIBAN_APPID=${!!H_CHIBAN_APPID}`);
  console.log(`EXB_CLIENT_DIST=${resolvedDist}`);
});
