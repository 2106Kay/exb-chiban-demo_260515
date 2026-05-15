// proxy.js - Render production proxy (final version, compatible with local ExB build output)
// Purpose:
// - Fully server-side fetch proxy for GEOSPACE chiban APIs and 法務省地番 APIs
// - Keeps widget unchanged: widget continues to call /api-chiban/* and /api-h-chiban/*
// - Handles TLS renegotiation compatibility via optional legacy OpenSSL flag
// - Absorbs CORS for browser clients
// - Adds origin restriction, simple rate limiting, admin endpoint, and detailed logs
//
// Deployment notes:
// - Replace existing proxy.js with this file and set environment variables in Render or your host:
//   PORT (optional), ALLOW_LEGACY_TLS (true|false), CHIBAN_APPID, H_CHIBAN_APPID,
//   ALLOWED_ORIGINS (comma separated), ADMIN_TOKEN (optional), RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX
// - To point static serving to a custom ExB build location, set EXB_CLIENT_DIST environment variable.
//   Example (local): EXB_CLIENT_DIST="D:\\ArcGISExperienceBuilder_119_chrome\\client\\dist"
//   Example (Render): EXB_CLIENT_DIST="./client/dist"
//
// Security notes:
// - ALLOW_LEGACY_TLS=true enables legacy renegotiation compatibility (security tradeoff). Use only if required.

const express = require('express');
const https = require('https');
const http = require('http');
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
const CHIBAN_APPID = process.env.CHIBAN_APPID || '';         // optional server-side appid for GEOSPACE chiban
const H_CHIBAN_APPID = process.env.H_CHIBAN_APPID || '';     // optional server-side appid for 法務省
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10); // 1 minute
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '120', 10); // requests per window per IP

// --- Simple in-memory rate limiter (IP-based) ---
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

// --- Legacy agent for OpenSSL renegotiation compatibility (optional) ---
let agent;
if (ALLOW_LEGACY_TLS) {
  try {
    agent = new https.Agent({
      secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT
    });
    console.log('proxy: ALLOW_LEGACY_TLS enabled');
  } catch (e) {
    agent = new https.Agent();
    console.warn('proxy: ALLOW_LEGACY_TLS requested but not available in this Node build; continuing without legacy flag');
  }
} else {
  agent = new https.Agent();
  console.log('proxy: ALLOW_LEGACY_TLS disabled');
}

// --- Utility: copy response headers excluding hop-by-hop ---
function copyResponseHeaders(srcHeaders, res) {
  const hopByHop = new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailers','transfer-encoding','upgrade']);
  Object.keys(srcHeaders || {}).forEach(k => {
    if (!hopByHop.has(k.toLowerCase())) {
      res.setHeader(k, srcHeaders[k]);
    }
  });
}

// --- Middleware: CORS / Origin check ---
app.use((req, res, next) => {
  const origin = req.headers.origin || req.headers.referer || '';
  if (ALLOWED_ORIGINS.length > 0) {
    const ok = ALLOWED_ORIGINS.some(o => origin.startsWith(o));
    if (!ok) {
      res.setHeader('Access-Control-Allow-Origin', 'null');
      return res.status(403).send('Origin not allowed');
    }
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// --- Simple request logging ---
app.use((req, res, next) => {
  console.log(`[incoming] ${req.method} ${req.originalUrl} ip:${req.ip} origin:${req.headers.origin || '-'}`);
  next();
});

// --- Health and admin endpoints ---
app.get('/__health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});
app.get('/__admin/status', (req, res) => {
  if (!ADMIN_TOKEN || req.headers['x-admin-token'] !== ADMIN_TOKEN) {
    return res.status(403).send('forbidden');
  }
  res.json({
    status: 'running',
    allowLegacyTls: ALLOW_LEGACY_TLS,
    rateLimitWindowMs: RATE_LIMIT_WINDOW_MS,
    rateLimitMax: RATE_LIMIT_MAX
  });
});

// --- Core proxy helper: perform server-side request to targetUrl and pipe response ---
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

    // Remove hop-by-hop headers that should not be forwarded
    delete opts.headers['host'];
    delete opts.headers['connection'];
    delete opts.headers['keep-alive'];
    delete opts.headers['transfer-encoding'];
    delete opts.headers['upgrade'];
    delete opts.headers['proxy-authorization'];
    delete opts.headers['proxy-authenticate'];

    // Ensure Accept header
    if (!opts.headers['accept']) opts.headers['accept'] = 'application/json';

    const proxyReq = https.request(opts, (proxyRes) => {
      res.statusCode = proxyRes.statusCode || 502;
      // Copy headers except hop-by-hop
      copyResponseHeaders(proxyRes.headers, res);
      // Ensure CORS headers are present for browser
      if (!res.getHeader('Access-Control-Allow-Origin')) {
        res.setHeader('Access-Control-Allow-Origin', '*');
      }
      proxyRes.pipe(res);
    });

    proxyReq.on('timeout', () => {
      console.error('[proxyRequestToTarget] timeout', targetUrl);
      proxyReq.destroy();
      if (!res.headersSent) res.status(504).send('Gateway Timeout');
    });

    proxyReq.on('error', (err) => {
      console.error('[proxyRequestToTarget] error', targetUrl, err && err.stack || err);
      if (!res.headersSent) res.status(502).json({ error: 'Proxy request failed' });
    });

    // If there is a body (POST/PUT), pipe it
    if (req.method && ['POST','PUT','PATCH'].includes(req.method.toUpperCase())) {
      req.pipe(proxyReq);
    } else {
      proxyReq.end();
    }
  } catch (err) {
    console.error('[proxyRequestToTarget] exception', err && err.stack || err);
    if (!res.headersSent) res.status(500).send('Internal Server Error');
  }
}

// --- Normalize endpoint path helper ---
function normalizeEndpointPath(basePath) {
  // basePath expected like '/api-chiban/searchChiban' or '/api-chiban/searchChiban/'
  // We want to map to '/api/searchChiban' on target host
  // Remove leading slash and api-chiban prefix
  let p = basePath || '';
  if (p.startsWith('/')) p = p.slice(1);
  // remove 'api-chiban' or 'chiban' or 'api-h-chiban' or 'houmu' prefixes
  p = p.replace(/^api-chiban\/?/, 'api/');
  p = p.replace(/^chiban\/?/, 'api/');
  p = p.replace(/^api-h-chiban\/?/, 'api/');
  p = p.replace(/^houmu\/?/, 'api/');
  if (!p.startsWith('api/')) p = 'api/' + p;
  return p;
}

// --- Main routes: handle /api-chiban and /chiban prefixes and /api-h-chiban and /houmu prefixes ---
// Use app.use for prefix matching to avoid path-to-regexp '*' parsing issues.

// Handler function reused for chiban endpoints
function chibanHandler(req, res) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) {
    console.warn('[rate] limit exceeded ip=%s url=%s', ip, req.originalUrl);
    return res.status(429).send('Too Many Requests');
  }

  const endpointPath = normalizeEndpointPath(req.path); // e.g., api/searchChiban
  const query = req.url.includes('?') ? req.url.split('?')[1] : '';
  const params = new URLSearchParams(query || '');
  if (!params.has('appid') && CHIBAN_APPID) {
    params.set('appid', CHIBAN_APPID);
  }
  const targetUrl = `https://api-chiban.geospace.jp/${endpointPath.replace(/^api\//,'api/')}${params.toString() ? '?' + params.toString() : ''}`;

  console.log('[proxy] chiban -> targetUrl=%s ip=%s method=%s', targetUrl, ip, req.method);
  proxyRequestToTarget(req, res, targetUrl);
}

// Handler function reused for houmu endpoints
function houmuHandler(req, res) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) {
    console.warn('[rate] limit exceeded ip=%s url=%s', ip, req.originalUrl);
    return res.status(429).send('Too Many Requests');
  }

  const endpointPath = normalizeEndpointPath(req.path);
  const query = req.url.includes('?') ? req.url.split('?')[1] : '';
  const params = new URLSearchParams(query || '');
  if (!params.has('appid') && H_CHIBAN_APPID) {
    params.set('appid', H_CHIBAN_APPID);
  }
  const targetUrl = `https://api-h-chiban.geospace.jp/${endpointPath.replace(/^api\//,'api/')}${params.toString() ? '?' + params.toString() : ''}`;

  console.log('[proxy] houmu -> targetUrl=%s ip=%s method=%s', targetUrl, ip, req.method);
  proxyRequestToTarget(req, res, targetUrl);
}

// Mount prefix handlers using app.use so subpaths are matched without '*' patterns
app.use('/chiban', chibanHandler);
app.use('/api-chiban', chibanHandler);
app.use('/houmu', houmuHandler);
app.use('/api-h-chiban', houmuHandler);

// --- Backwards-compatible simple proxy endpoints (optional) ---
app.get('/api-chiban-proxy', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) {
    console.warn('[rate] limit exceeded ip=%s url=%s', ip, req.originalUrl);
    return res.status(429).send('Too Many Requests');
  }
  const params = new URLSearchParams(req.query);
  if (!params.has('appid') && CHIBAN_APPID) params.set('appid', CHIBAN_APPID);
  const targetUrl = `https://api-chiban.geospace.jp/api/searchChiban?${params.toString()}`;
  console.log('[proxy] /api-chiban-proxy -> %s', targetUrl);
  proxyRequestToTarget(req, res, targetUrl);
});

app.get('/api-h-chiban-proxy', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) {
    console.warn('[rate] limit exceeded ip=%s url=%s', ip, req.originalUrl);
    return res.status(429).send('Too Many Requests');
  }
  const params = new URLSearchParams(req.query);
  if (!params.has('appid') && H_CHIBAN_APPID) params.set('appid', H_CHIBAN_APPID);
  const targetUrl = `https://api-h-chiban.geospace.jp/api/searchChiban?${params.toString()}`;
  console.log('[proxy] /api-h-chiban-proxy -> %s', targetUrl);
  proxyRequestToTarget(req, res, targetUrl);
});

// --- Static assets (Experience Builder build output) ---
// Prefer environment override for flexibility in Render or other hosts.
// EXB_CLIENT_DIST can be absolute (Windows path) or relative to this repo.
const EXB_CLIENT_DIST = process.env.EXB_CLIENT_DIST || path.join('D:', 'ArcGISExperienceBuilder_119_chrome', 'client', 'dist');
const resolvedDist = path.isAbsolute(EXB_CLIENT_DIST) ? EXB_CLIENT_DIST : path.join(__dirname, EXB_CLIENT_DIST);

// Log resolved path for debugging
console.log('proxy: serving ExB client dist from', resolvedDist);

// If the directory doesn't exist, warn but keep server running (so API proxy still works)
if (!fs.existsSync(resolvedDist)) {
  console.warn(`proxy: EXB client dist path does not exist: ${resolvedDist}`);
}

// Serve static files under the expected route
app.use('/cdn/1/jimu-core', express.static(resolvedDist, {
  maxAge: '1d',
  index: false
}));

// SPA fallback for that route: always return dist/index.html
// Use prefix-based middleware instead of wildcard route to avoid path-to-regexp '*' parsing issues.
app.use('/cdn/1/jimu-core', (req, res, next) => {
  if (req.method === 'GET' && req.accepts('html')) {
    const indexPath = path.join(resolvedDist, 'index.html');
    if (!fs.existsSync(indexPath)) {
      console.error('sendFile /cdn/1/jimu-core index.html not found at', indexPath);
      return res.status(404).send('Not Found');
    }
    return res.sendFile(indexPath, (err) => {
      if (err) {
        console.error('sendFile /cdn/1/jimu-core index.html error:', err && err.message);
        res.status(500).send('Internal Server Error');
      }
    });
  }
  next();
});

// Also keep root fallback to the same index (optional)
app.get('/', (req, res) => {
  const indexPath = path.join(resolvedDist, 'index.html');
  if (!fs.existsSync(indexPath)) {
    console.error('sendFile / index.html not found at', indexPath);
    return res.status(404).send('Not Found');
  }
  res.sendFile(indexPath, (err) => {
    if (err) {
      console.error('sendFile / index.html error:', err && err.message);
      res.status(500).send('Internal Server Error');
    }
  });
});

// Fallback for other GET requests that accept HTML (SPA behavior)
app.use((req, res, next) => {
  if (req.method === 'GET' && req.accepts('html')) {
    const indexPath = path.join(resolvedDist, 'index.html');
    if (!fs.existsSync(indexPath)) {
      return res.status(404).send('Not Found');
    }
    return res.sendFile(indexPath, (err) => {
      if (err) {
        console.error('fallback sendFile error:', err && err.message);
        res.status(500).send('Internal Server Error');
      }
    });
  }
  next();
});

// 404 handler
app.use((req, res) => {
  res.status(404).send('Not Found');
});

// Start server
app.listen(PORT, () => {
  console.log(`Proxy server listening on port ${PORT}`);
  console.log(`ALLOW_LEGACY_TLS=${ALLOW_LEGACY_TLS} CHIBAN_APPID=${!!CHIBAN_APPID} H_CHIBAN_APPID=${!!H_CHIBAN_APPID}`);
  console.log(`EXB_CLIENT_DIST=${resolvedDist}`);
});
