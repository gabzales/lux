/**
 * httpjson.js — klien HTTP(S) JSON minimal (tanpa dependensi, tidak butuh fetch global,
 * jalan di Node versi berapa pun). Dipakai ghostseller.js dan genspay.js.
 *
 * Mengembalikan { status, json, text } — TIDAK melempar untuk status non-2xx
 * (pemanggil yang memutuskan), hanya melempar untuk error jaringan / timeout /
 * URL tidak valid, dengan err.code = 'network' | 'timeout' | 'bad_url'.
 * Header (termasuk API key) tidak pernah ikut ke pesan error.
 */
const http = require('http');
const https = require('https');
const { URL } = require('url');

const MAX_BYTES = 1024 * 1024; // 1 MB — respons API provider tidak perlu lebih dari ini

const MAX_REDIRECTS = 3;
const bareHost = (h) => String(h || '').toLowerCase().replace(/^www\./, '');

/**
 * Ikuti redirect (301/302/303/307/308) maks. 3x. Header (termasuk API key) HANYA diteruskan bila host tujuan
 * sama dengan host asal atau hanya beda awalan "www." (mis. apex → www); selain itu redirect ditolak.
 * 307/308 mempertahankan method+body; 301/302/303 pada POST berubah jadi GET tanpa body (perilaku standar).
 */
async function requestJson(urlStr, opts = {}) {
  let url = urlStr, o = opts;
  for (let hop = 0; ; hop++) {
    const r = await requestJsonOnce(url, o);
    const loc = r.headers && r.headers.location;
    if (![301, 302, 303, 307, 308].includes(r.status) || !loc) return r;
    if (hop >= MAX_REDIRECTS) { const e = new Error('Terlalu banyak redirect'); e.code = 'network'; throw e; }
    let next, from;
    try { from = new URL(url); next = new URL(loc, url); } catch { const e = new Error('Redirect tidak valid'); e.code = 'bad_url'; throw e; }
    if (next.protocol !== 'https:' && next.protocol !== 'http:') { const e = new Error('Redirect ke protokol tidak didukung'); e.code = 'bad_url'; throw e; }
    if (bareHost(next.hostname) !== bareHost(from.hostname) || (from.protocol === 'https:' && next.protocol !== 'https:')) {
      const e = new Error('Redirect ke host lain ditolak (' + next.hostname + ')'); e.code = 'network'; throw e;
    }
    const keepMethod = r.status === 307 || r.status === 308;
    o = keepMethod ? o : { ...o, method: 'GET', body: undefined };
    url = next.toString();
  }
}

function requestJsonOnce(urlStr, { method = 'GET', headers = {}, body, timeoutMs = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlStr); } catch { const e = new Error('URL tidak valid'); e.code = 'bad_url'; return reject(e); }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') { const e = new Error('Protokol URL tidak didukung'); e.code = 'bad_url'; return reject(e); }

    const payload = body === undefined ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const h = { Accept: 'application/json', ...headers };
    if (payload !== null) {
      h['Content-Type'] = h['Content-Type'] || 'application/json';
      h['Content-Length'] = Buffer.byteLength(payload);
    }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method, headers: h,
    }, (res) => {
      let size = 0; const chunks = [];
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_BYTES) { req.destroy(); const e = new Error('Respons terlalu besar'); e.code = 'network'; reject(e); return; }
        chunks.push(c);
      });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch { json = null; }
        resolve({ status: res.statusCode || 0, json, text, headers: res.headers || {} });
      });
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); const e = new Error(`Timeout setelah ${Math.round(timeoutMs / 1000)} detik`); e.code = 'timeout'; reject(e); });
    req.on('error', (err) => { if (err.code === 'timeout') return reject(err); const e = new Error('Gagal terhubung: ' + (err.code || err.message)); e.code = 'network'; reject(e); });
    if (payload !== null) req.write(payload);
    req.end();
  });
}

module.exports = { requestJson };
