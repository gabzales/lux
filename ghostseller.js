/**
 * ghostseller.js — Klien Ghostseller Partner API v1 (satu-satunya provider auto-restock).
 *
 * Kontrak (dari docs Ghostseller /docs/api-v1):
 *   Header   : X-API-Key: gs_partner_...
 *   GET  {BASE}/products      -> { data: [{ id, name, category, active, product_durations:[{id,label,days,price,base_price}] }] }
 *   POST {BASE}/generate-key  body { productId, durationId, idempotencyKey }
 *                             -> { key: { id, key_string, price, ... } }
 *   Error    : { error: "kode", message: "..." }  (401, 400, 402, 404, 409, 429, 502, 500)
 *
 * Konfigurasi HANYA lewat environment (tidak pernah disimpan di database / dikirim ke browser):
 *   GHOSTSELLER_API_KEY   wajib
 *   GHOSTSELLER_API_URL   opsional, default https://ghostseller.my.id
 *                         (boleh domain saja, mis. https://xxx.vercel.app, atau URL lengkap .../api/v1/partner)
 *
 * Aturan pemakaian dari Ghostseller yang dipatuhi di sini:
 *   - katalog JANGAN dipanggil per pengunjung -> di-cache 5 menit
 *   - idempotencyKey = kode order -> retry tidak pernah menerbitkan 2 key (& tidak memotong saldo 2x)
 *   - 402 / 409 -> jangan di-retry cepat; 429 / 502 / timeout -> boleh dicoba lagi
 */
const { requestJson } = require('./httpjson');

const DEFAULT_URL = 'https://ghostseller.my.id';
const CATALOG_TTL_MS = 5 * 60 * 1000;
const GENERATE_TIMEOUT_MS = 30000; // docs menyarankan >= 35s; dibatasi 30s agar muat di batas fungsi Vercel
const CATALOG_TIMEOUT_MS = 12000;

const getConfig = () => {
  const apiKey = (process.env.GHOSTSELLER_API_KEY || '').trim();
  let base = (process.env.GHOSTSELLER_API_URL || DEFAULT_URL).trim().replace(/\/+$/, '');
  if (!/\/api\/v1\/partner$/i.test(base)) base += '/api/v1/partner';
  return { apiKey, base };
};

const isConfigured = () => !!getConfig().apiKey;

class GhostsellerError extends Error {
  constructor(code, message, { status = 0, transient = false } = {}) {
    super(message);
    this.name = 'GhostsellerError';
    this.code = code;         // unauthorized | insufficient_balance | out_of_stock | invalid_product_or_duration | rate_limited | provider_error | timeout | network | not_configured | unknown
    this.status = status;
    this.transient = transient; // true = aman dicoba lagi nanti (idempotencyKey mencegah dobel)
  }
}

// Peta status/kode Ghostseller -> klasifikasi
const TRANSIENT_CODES = new Set(['rate_limited', 'provider_error', 'timeout', 'network']);

function toError(status, json, fallbackText) {
  const code = (json && json.error) || (status === 401 ? 'unauthorized' : status === 402 ? 'insufficient_balance' : status === 409 ? 'out_of_stock' : status === 429 ? 'rate_limited' : status === 502 ? 'provider_error' : 'unknown');
  const msg = (json && json.message) || (json && json.error) || (fallbackText || '').slice(0, 120) || `HTTP ${status}`;
  const transient = TRANSIENT_CODES.has(code) || status === 429 || status === 502 || status === 503 || status === 504 || (status >= 500 && code === 'unknown');
  return new GhostsellerError(code, msg, { status, transient });
}

async function call(path, opts) {
  const { apiKey, base } = getConfig();
  if (!apiKey) throw new GhostsellerError('not_configured', 'GHOSTSELLER_API_KEY belum diisi di environment.');
  let r;
  try {
    r = await requestJson(base + path, { ...opts, headers: { 'X-API-Key': apiKey } });
  } catch (e) {
    throw new GhostsellerError(e.code === 'timeout' ? 'timeout' : 'network', e.message, { transient: true });
  }
  if (r.status >= 200 && r.status < 300) return r.json;
  throw toError(r.status, r.json, r.text);
}

// ── Katalog (cache 5 menit; stale dipakai kalau refresh gagal) ──
let catalogCache = { at: 0, data: null };

/** @returns {Promise<Array<{id,name,category,active,durations:Array<{id,label,days,price,basePrice}>}>>} */
async function fetchCatalog({ force = false } = {}) {
  if (!force && catalogCache.data && Date.now() - catalogCache.at < CATALOG_TTL_MS) return catalogCache.data;
  try {
    const json = await call('/products', { method: 'GET', timeoutMs: CATALOG_TIMEOUT_MS });
    const list = Array.isArray(json && json.data) ? json.data : [];
    const data = list.map((p) => ({
      id: String(p.id),
      name: String(p.name || p.id),
      category: p.category || '',
      active: p.active !== false,
      durations: (Array.isArray(p.product_durations) ? p.product_durations : []).map((d) => ({
        id: String(d.id),
        label: String(d.label || d.id),
        days: Number(d.days) || 0,
        price: Number(d.price) || 0,
        basePrice: Number(d.base_price) || 0,
      })),
    }));
    catalogCache = { at: Date.now(), data };
    return data;
  } catch (e) {
    if (catalogCache.data && !force) return catalogCache.data; // lebih baik katalog agak basi daripada error
    throw e;
  }
}

/** Cek cepat apakah pasangan produk+durasi masih ada & aktif di katalog (pakai cache; gagal-terbuka). */
async function isListed(productId, durationId) {
  try {
    const cat = await fetchCatalog();
    const p = cat.find((x) => x.id === productId);
    return !!(p && p.active && p.durations.some((d) => d.id === durationId));
  } catch {
    return true; // katalog tak terjangkau ≠ produk hilang; biarkan generate-key yang memutuskan
  }
}

/**
 * Generate 1 key. Memotong saldo akun reseller yang terikat ke API key. Tidak bisa dibatalkan.
 * @returns {Promise<{keyString:string, id:string, price:number}>}
 * @throws {GhostsellerError}
 */
async function generateKey({ productId, durationId, idempotencyKey }) {
  if (!productId || !durationId) throw new GhostsellerError('invalid_product_or_duration', 'Mapping Ghostseller belum lengkap (productId/durationId kosong).');
  const json = await call('/generate-key', {
    method: 'POST',
    body: { productId: String(productId), durationId: String(durationId), idempotencyKey: String(idempotencyKey || '') || undefined },
    timeoutMs: GENERATE_TIMEOUT_MS,
  });
  const k = json && json.key;
  if (!k || !k.key_string) throw new GhostsellerError('provider_error', 'Respons generate-key tidak berisi key_string.', { transient: true });
  return { keyString: String(k.key_string), id: String(k.id || ''), price: Number(k.price) || 0 };
}

module.exports = { name: 'ghostseller', label: 'Ghostseller', idempotent: true, isConfigured, fetchCatalog, isListed, generateKey, GhostsellerError, _getConfig: getConfig, _resetCache: () => { catalogCache = { at: 0, data: null }; } };
