/**
 * dripstore.js — Klien DRIP STORE Reseller API (provider auto-restock).
 *
 * Kontrak (dari dripstore-client.js / docs resmi):
 *   Header : X-API-Token: <token>
 *   GET  {BASE}/balance.php | products.php | reset_apis.php | key_history.php?limit=N
 *   POST {BASE}/generate_key.php   (form-urlencoded) variant_id, quantity, [api_version], [android_id]
 *   products.php -> DAFTAR DATAR varian { success, count, products:[{ variant_id, product_id, product_name, variant_name, price(USD), in_stock, unlimited, ... }] }
 *   (respons sukses TANPA pembungkus `data`; bentuk asli terverifikasi dari probe produksi)
 *   Error  : 401 token | 403 (IP) | 423 cap | 429 rate limit (Retry-After) | 5xx
 *            Origin 5xx dibungkus HTTP 200 {success:false, code, error} → SELALU cek field `success`.
 *   Cloudflare: bila IP server belum di-allowlist toko, yang kembali halaman HTML challenge (bukan JSON).
 *
 * Konfigurasi HANYA lewat environment (tidak pernah di database / dikirim ke browser):
 *   DRIPSTORE_API_TOKEN   wajib
 *   DRIPSTORE_API_URL     opsional, default https://dripclientstore.shop/api/v1
 *
 * ⚠ TIDAK ADA idempotency key di API ini. Mengulang generate_key setelah timeout/jaringan putus bisa
 *   memotong saldo DUA kali. Karena itu: error yang "mungkin sudah memotong saldo" ditandai
 *   `maybeCharged` dan TIDAK PERNAH di-retry otomatis (lihat deliverPaidOrder di server.js).
 *
 * Batasan: varian Bala Mod mode "v1" butuh Android ID pembeli → ditandai `unsupported` (tidak bisa dipetakan).
 */
const { requestJson } = require('./httpjson');
const dur = require('./durations');

const DEFAULT_URL = 'https://dripclientstore.shop/api/v1';
const GENERATE_TIMEOUT_MS = 30000;
const CATALOG_TIMEOUT_MS = 12000;

const getConfig = () => {
  const token = (process.env.DRIPSTORE_API_TOKEN || '').trim();
  let base = (process.env.DRIPSTORE_API_URL || DEFAULT_URL).trim().replace(/\/+$/, '');
  if (!/\/api\/v1$/i.test(base)) base += '/api/v1';
  return { token, base };
};
const isConfigured = () => !!getConfig().token;

class DripStoreError extends Error {
  constructor(code, message, { status = 0, transient = false, maybeCharged = false } = {}) {
    super(message);
    this.name = 'DripStoreError';
    this.code = code;               // not_configured | unauthorized | ip_blocked | forbidden | key_cap | rate_limited | cloudflare_challenge | insufficient_balance | out_of_stock | invalid_product_or_duration | provider_error | timeout | network | bad_reply | unparseable_success | bad_config
    this.status = status;
    this.transient = transient;     // aman dicoba lagi (permintaan PASTI belum diproses)
    this.maybeCharged = maybeCharged; // saldo MUNGKIN sudah terpotong → jangan retry buta
  }
}

const isChallenge = (text, status) => {
  const b = String(text || '').trimStart();
  if (/Just a moment|cf-browser-verification|challenge-platform|cf-chl/i.test(b)) return true;
  return b.startsWith('<') && status < 500; // HTML tak terduga pada 2xx/4xx = hampir pasti halaman Cloudflare
};

// Klasifikasi {success:false, code, error} dari origin
function classifyFailure(j) {
  const text = `${j.code || ''} ${j.error || ''} ${j.message || ''}`;
  const msg = String(j.error || j.message || j.code || 'Permintaan ditolak').slice(0, 200);
  if (/balance|saldo|insufficient|funds?|credit/i.test(text)) return ['insufficient_balance', msg];
  if (/stock|stok|out[ _-]?of|habis|sold[ _-]?out|no keys?|empty/i.test(text)) return ['out_of_stock', msg];
  if (/rate/i.test(text)) return ['rate_limited', msg];
  if (/variant|product|not[ _-]?found|invalid|inactive|disabled|unavailable/i.test(text)) return ['invalid_product_or_duration', msg];
  return ['provider_error', msg];
}

async function call(endpoint, { method = 'GET', params = {}, timeoutMs = 15000, generate = false } = {}) {
  const { token, base } = getConfig();
  if (!token) throw new DripStoreError('not_configured', 'DRIPSTORE_API_TOKEN belum diisi di environment.');
  let url = base + '/' + endpoint;
  const headers = { 'X-API-Token': token };
  let body;
  if (method === 'GET') {
    const qs = new URLSearchParams(params).toString();
    if (qs) url += '?' + qs;
  } else {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(params).toString();
  }

  let r;
  try {
    r = await requestJson(url, { method, headers, body, timeoutMs });
  } catch (e) {
    if (e.code === 'bad_url') throw new DripStoreError('bad_config', 'DRIPSTORE_API_URL tidak valid.');
    // Untuk generate: putus di tengah jalan = TIDAK DIKETAHUI apakah sudah diproses.
    throw new DripStoreError(e.code === 'timeout' ? 'timeout' : 'network', e.message, { transient: !generate, maybeCharged: generate });
  }

  if (isChallenge(r.text, r.status)) {
    throw new DripStoreError('cloudflare_challenge',
      'Cloudflare menahan request (IP server ini kemungkinan belum di-allowlist oleh Drip Store). API token kamu sendiri tidak bermasalah.',
      { status: r.status });
  }
  const j = r.json;

  if (r.status === 401) throw new DripStoreError('unauthorized', (j && j.error) || 'Token tidak valid / dicabut', { status: 401 });
  if (r.status === 403) {
    const msg = (j && j.error) || 'Forbidden';
    throw new DripStoreError(/ip/i.test(msg) ? 'ip_blocked' : 'forbidden', msg, { status: 403 });
  }
  if (r.status === 423) throw new DripStoreError('key_cap', (j && j.error) || 'Batas per-key tercapai', { status: 423 });
  if (r.status === 429) throw new DripStoreError('rate_limited', (j && j.error) || 'Rate limit', { status: 429, transient: true }); // ditolak sebelum diproses → aman di-retry
  if (r.status >= 500) throw new DripStoreError('provider_error', `Server Drip Store error ${r.status}`, { status: r.status, transient: !generate, maybeCharged: generate });
  if (!j || typeof j !== 'object') {
    throw new DripStoreError('bad_reply', `Respons bukan JSON (HTTP ${r.status})`, { status: r.status, transient: !generate, maybeCharged: generate });
  }
  if (j.success === false) {
    const [code, msg] = classifyFailure(j);
    throw new DripStoreError(code, msg, { status: r.status, transient: code === 'rate_limited' });
  }
  return j;
}

// ── Katalog ──
// BENTUK ASLI (terverifikasi dari probe produksi): products.php = DAFTAR DATAR varian, sukses TANPA pembungkus `data`:
//   { success, count, products:[ { variant_id, product_id, product_name, variant_name, platform, validity, validity_unit,
//     price:"0.20"(USD, string), currency, in_stock, local_stock, stock_source, unlimited, is_balamod, api_version_mode,
//     supports_v1, supports_v2, requires_android_id } ] }
// CATATAN data: `validity_unit` TIDAK bisa dipercaya (varian BALAMOD "1 Hour" tercatat unit "days"; "24 Hours (1 Day)" = 24 "days"),
//   jadi durasi dibaca dari LABEL dulu; kolom validity hanya cadangan.
const CATALOG_TTL_MS = 60 * 1000;   // stok berubah cepat → cache pendek (1 menit); aman untuk rate limit 60 req/menit
const BALANCE_TTL_MS = 30 * 1000;
let catalogCache = { at: 0, data: null };
let balanceCache = { at: 0, data: null };

const isV1Only = (v) => v.requires_android_id === true || (!!v.is_balamod && String(v.api_version_mode || '').toLowerCase() === 'v1');

function variantDuration(v) {
  const parsed = dur.parseDuration(v.variant_name || v.name || v.label);
  if (parsed) return parsed;
  const n = parseInt(v.validity ?? v.validity_days ?? v.days, 10);
  const unit = /^hour/i.test(String(v.validity_unit || '')) ? 'hour' : 'day';
  return n > 0 ? { n, unit } : { n: 0, unit: 'day' };
}

/** Samakan bentuk dengan Ghostseller: [{id,name,category,active,durations:[{id,label,n,unit,price,currency,stock,unlimited,...}]}] */
function normalizeCatalog(j) {
  const list = (j.data && j.data.products) || j.products || [];
  const arr = Array.isArray(list) ? list : [];
  const byProduct = new Map();
  const ensure = (id, name, category) => {
    if (!byProduct.has(id)) byProduct.set(id, { id, name, category: category || '', active: true, durations: [] });
    return byProduct.get(id);
  };
  for (const v of arr) {
    if (v && v.variant_id !== undefined) {                       // bentuk asli: datar
      const prod = ensure(String(v.product_id), String(v.product_name || ('Produk ' + v.product_id)).trim(), v.platform);
      prod.durations.push(mapVariant(v, v.variant_id));
    } else if (v && Array.isArray(v.variants)) {                  // cadangan: bentuk bersarang (docs lama)
      const prod = ensure(String(v.id), String(v.name || v.title || ('Produk ' + v.id)), v.category);
      for (const x of v.variants) prod.durations.push(mapVariant(x, x.id));
    }
  }
  const out = [...byProduct.values()];
  for (const p of out) {
    const seen = new Set();
    p.durations = p.durations.filter((d) => !seen.has(d.id) && seen.add(d.id))
      .sort((a, b) => dur.totalHours(a.n, a.unit) - dur.totalHours(b.n, b.unit) || a.price - b.price);
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

function mapVariant(v, id) {
  const { n, unit } = variantDuration(v);
  const unlimited = v.unlimited === true;
  return {
    id: String(id),
    label: String(v.variant_name || v.name || v.label || ('Varian ' + id)).trim(),
    n, unit, days: unit === 'day' ? n : 0,
    price: Number(v.price ?? v.cost) || 0,
    basePrice: Number(v.price ?? v.cost) || 0,
    currency: String(v.currency || 'USD'),
    stock: unlimited ? 999999 : (Number(v.in_stock) || 0),
    unlimited,
    stockSource: v.stock_source || '',
    active: true,
    mode: v.is_balamod ? String(v.api_version_mode || 'v2').toLowerCase() : '',
    unsupported: isV1Only(v) ? 'Butuh Android ID pembeli (belum didukung checkout otomatis)' : '',
  };
}

async function fetchCatalog({ force = false } = {}) {
  if (!force && catalogCache.data && Date.now() - catalogCache.at < CATALOG_TTL_MS) return catalogCache.data;
  try {
    const j = await call('products.php', { timeoutMs: CATALOG_TIMEOUT_MS });
    const data = normalizeCatalog(j);
    catalogCache = { at: Date.now(), data };
    return data;
  } catch (e) {
    if (catalogCache.data && !force) return catalogCache.data;
    throw e;
  }
}

/** Saldo reseller { balance:Number, currency } — cache 30 dtk. */
async function getBalance({ force = false } = {}) {
  if (!force && balanceCache.data && Date.now() - balanceCache.at < BALANCE_TTL_MS) return balanceCache.data;
  const j = await call('balance.php', { timeoutMs: CATALOG_TIMEOUT_MS });
  const data = { balance: Number(j.balance), currency: String(j.currency || 'USD') };
  balanceCache = { at: Date.now(), data };
  return data;
}

const findVariant = (cat, productId, variantId) => {
  const p = (cat || []).find((x) => x.id === String(productId));
  return { p, d: p && p.durations.find((x) => x.id === String(variantId)) };
};
const variantOk = (d) => !!d && d.active !== false && !d.unsupported && (d.unlimited || d.stock > 0);

/**
 * Preflight sebelum pembeli membayar: varian ada, didukung, STOK > 0 (atau unlimited), dan SALDO cukup.
 * Gagal-terbuka kalau provider tak terjangkau (generate_key yang memutuskan).
 */
async function isListed(productId, variantId) {
  try {
    const cat = await fetchCatalog();
    const { d } = findVariant(cat, productId, variantId);
    if (!variantOk(d)) return false;
    try {
      const b = await getBalance();
      if (Number.isFinite(b.balance) && d.price > 0 && b.balance + 1e-9 < d.price) return false; // saldo tak cukup → jangan jual
    } catch { /* saldo tak terbaca: lanjut */ }
    return true;
  } catch {
    return true;
  }
}

/** Sinkron, tanpa panggilan jaringan: true/false dari cache terakhir, null = belum diketahui (dianggap tersedia). */
function peekAvailability(productId, variantId) {
  if (!catalogCache.data) return null;
  const { d } = findVariant(catalogCache.data, productId, variantId);
  if (!d) return false;
  if (!variantOk(d)) return false;
  const b = balanceCache.data;
  if (b && Number.isFinite(b.balance) && d.price > 0 && b.balance + 1e-9 < d.price) return false;
  return true;
}

// ── Ekstrak key dari respons generate_key.php ──
// Respons produksi bersifat DATAR (tanpa `data`), dan key riwayat berupa array string `keys:[...]`.
// Field generik (code/value/…) SENGAJA tidak dipakai: respons memuat angka/status lain yang bukan key.
const KEY_FIELDS = ['keys', 'key', 'key_string', 'license_key', 'license', 'licenses', 'serial', 'items', 'results'];
function pickKey(v, depth = 0) {
  if (v == null || depth > 4) return null;
  if (typeof v === 'string') return v.trim() || null;
  if (Array.isArray(v)) { for (const x of v) { const k = pickKey(x, depth + 1); if (k) return k; } return null; }
  if (typeof v === 'object') {
    for (const f of KEY_FIELDS) { const k = pickKey(v[f], depth + 1); if (k) return k; }
    if (v.username != null && v.password != null) return `${v.username}:${v.password}`;
    if (v.username != null) return String(v.username);
    if (v.data && typeof v.data === 'object') return pickKey(v.data, depth + 1);
  }
  return null;
}

/**
 * Generate 1 key (variantId = variant_id Drip Store). Memotong saldo reseller (USD). Tidak ada idempotency.
 * @returns {Promise<{keyString:string, id:string, price:number, currency:string}>}
 * @throws {DripStoreError}  — periksa e.maybeCharged sebelum memutuskan retry
 */
async function generateKey({ productId, durationId }) {
  const variantId = parseInt(durationId, 10);
  if (!Number.isFinite(variantId) || variantId <= 0) throw new DripStoreError('invalid_product_or_duration', 'Mapping Drip Store belum lengkap (variant_id kosong).');

  const params = { variant_id: variantId, quantity: 1 }; // toko menjual 1 key per order; Bala Mod memang selalu 1
  try {
    const cat = await fetchCatalog();
    const { d: v } = findVariant(cat, productId, variantId);
    if (v && v.unsupported) throw new DripStoreError('invalid_product_or_duration', 'Varian ini butuh Android ID pembeli dan belum didukung.');
    if (v && v.mode === 'both') params.api_version = 'v2'; // v2 = key langsung tanpa Android ID
  } catch (e) { if (e instanceof DripStoreError && e.code === 'invalid_product_or_duration') throw e; /* katalog gagal: server tetap memvalidasi */ }

  const j = await call('generate_key.php', { method: 'POST', params, timeoutMs: GENERATE_TIMEOUT_MS, generate: true });
  const key = pickKey(j);
  if (!key) {
    // Sukses menurut server (saldo kemungkinan terpotong) tapi bentuk respons tak dikenali → JANGAN hilangkan, laporkan mentah.
    throw new DripStoreError('unparseable_success', 'Key terbit tapi format respons tidak dikenali: ' + JSON.stringify(j).slice(0, 300), { maybeCharged: true });
  }
  const o = (j.data && typeof j.data === 'object') ? j.data : j;
  const price = Number(o.total_amount ?? o.unit_price ?? o.price ?? o.cost ?? o.charged) || 0;
  balanceCache = { at: 0, data: null }; // saldo berubah setelah generate
  return { keyString: key, id: String(o.order_id ?? o.id ?? ''), price, currency: String(o.currency || 'USD') };
}

// ── Probe: kumpulkan CONTOH RESPONS (baca-saja) untuk dianalisis — dipanggil dari tombol di Admin ──
// Token tidak pernah ikut; nilai field bernama key/license/password/token/secret/serial/android disamarkan
// (struktur JSON tetap utuh). Tidak ada panggilan yang memotong saldo: generate_key hanya dicoba dengan
// variant_id fiktif untuk melihat bentuk respons ERROR.
const SENSITIVE = /(key|license|passw|token|secret|serial|android)/i;
const maskVal = (v) => { const s = String(v); return s.length <= 4 ? '****' : s.slice(0, 4) + '…(' + s.length + ' char)'; };
function redact(x, keyName = '') {
  if (Array.isArray(x)) return x.map((i) => redact(i, keyName));
  if (x && typeof x === 'object') return Object.fromEntries(Object.entries(x).map(([k, v]) => [k, redact(v, k)]));
  if ((typeof x === 'string' || typeof x === 'number') && SENSITIVE.test(keyName) && String(x).length > 0) return maskVal(x);
  return x;
}

async function probe() {
  const { token, base } = getConfig();
  if (!token) throw new DripStoreError('not_configured', 'DRIPSTORE_API_TOKEN belum diisi di environment.');
  const scrub = (t) => String(t).split(token).join('[TOKEN]');
  const report = { when: new Date().toISOString(), base, calls: [] };
  try { report.egressIp = scrub((await requestJson('https://api.ipify.org', { timeoutMs: 6000 })).text.trim().slice(0, 45)); }
  catch { report.egressIp = '(gagal dicek)'; }

  const steps = [
    ['saldo', 'balance.php'],
    ['daftar produk', 'products.php'],
    ['API reset', 'reset_apis.php'],
    ['riwayat', 'key_history.php', { params: { limit: 5 } }],
    ['BENTUK ERROR: varian fiktif (tidak memotong saldo)', 'generate_key.php', { method: 'POST', params: { variant_id: 999999999, quantity: 1 } }],
  ];
  for (const [label, endpoint, o = {}] of steps) {
    const method = o.method || 'GET', params = o.params || {};
    let url = base + '/' + endpoint; const headers = { 'X-API-Token': token }; let body;
    if (method === 'GET') { const qs = new URLSearchParams(params).toString(); if (qs) url += '?' + qs; }
    else { headers['Content-Type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(params).toString(); }
    const out = { label, request: `${method} /${endpoint}` + (method === 'GET' && Object.keys(params).length ? '?' + new URLSearchParams(params) : '') };
    const t0 = Date.now();
    try {
      const r = await requestJson(url, { method, headers, body, timeoutMs: 9000 });
      out.http = r.status; out.ms = Date.now() - t0;
      out.contentType = r.headers['content-type'] || null;
      out.retryAfter = r.headers['retry-after'] || null;
      out.cloudflare = r.headers['cf-ray'] ? 'ya' : 'tidak';
      const head = String(r.text || '').trimStart();
      if (head.startsWith('<')) { out.kind = isChallenge(head, r.status) ? 'CLOUDFLARE_CHALLENGE (IP server ini belum di-allowlist)' : 'HTML (bukan JSON)'; out.body = scrub(head.slice(0, 200)); }
      else if (r.json !== null) { out.kind = 'json'; out.body = redact(r.json); }
      else { out.kind = 'bukan JSON'; out.body = scrub(head.slice(0, 300)); }
    } catch (e) { out.error = scrub(e.message); }
    report.calls.push(out);
    await new Promise((res) => setTimeout(res, 300));
  }
  return JSON.parse(scrub(JSON.stringify(report)));
}

module.exports = {
  probe,
  name: 'dripstore', label: 'Drip Store', idempotent: false,
  isConfigured, fetchCatalog, getBalance, isListed, peekAvailability, generateKey, DripStoreError, _normalizeCatalog: normalizeCatalog,
  _getConfig: getConfig, _resetCache: () => { catalogCache = { at: 0, data: null }; balanceCache = { at: 0, data: null }; },
};
