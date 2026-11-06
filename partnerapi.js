/**
 * partnerapi.js — Pabrik klien "Partner API v1" (kontrak Ghostseller / Gneseller).
 *
 * Kontrak (docs /docs/api-v1 pada kedua panel — identik):
 *   Header   : X-API-Key: gs_partner_...
 *   GET  {BASE}/products      -> { data: [{ id, name, category, active, product_durations:[{id,label,days,price,base_price}] }] }
 *   POST {BASE}/generate-key  body { productId, durationId, idempotencyKey }
 *                             -> { key: { id, key_string, price, ... } }
 *   Error    : { error: "kode", message: "..." }  (401, 400, 402, 404, 409, 429, 502, 500)
 *
 * Satu pabrik, banyak instans: ghostseller.js dan gneseller.js memanggil createPartnerClient()
 * dengan env & URL masing-masing, sehingga dua panel bisa aktif bersamaan dengan kredensial terpisah.
 *
 * Aturan pemakaian yang dipatuhi:
 *   - katalog JANGAN dipanggil per pengunjung -> di-cache 5 menit
 *   - idempotencyKey = kode order -> retry tidak pernah menerbitkan 2 key (& tidak memotong saldo 2x)
 *   - 402 / 409 -> jangan di-retry cepat; 429 / 502 / timeout -> boleh dicoba lagi
 *
 * Durasi katalog: panel hanya menyimpan `days` (bilangan bulat), jadi varian JAM biasanya tercatat
 * days=1 dengan label "… 1 HOURS". Karena itu durasi dibaca dari LABEL dulu (n + unit, sama seperti
 * dripstore.js); `days` hanya cadangan. Tanpa ini, "1 Hari" dan "1 Jam" tampak sama-sama days=1.
 */
const { requestJson } = require('./httpjson');
const dur = require('./durations');

const CATALOG_TTL_MS = 5 * 60 * 1000;
const GENERATE_TIMEOUT_MS = 30000; // docs menyarankan >= 35s; dibatasi 30s agar muat di batas fungsi Vercel
const CATALOG_TIMEOUT_MS = 12000;
const TRANSIENT_CODES = new Set(['rate_limited', 'provider_error', 'timeout', 'network']);

function createPartnerClient({ name, label, envKey, envUrl, defaultUrl = '' }) {
  // Kredensial dari Admin → Pengaturan → Auto-Restock Provider (settings.providers.<name>); env dipakai bila kosong.
  let runtime = { apiKey: '', url: '' };
  const cleanKey = (v) => String(v || '').trim().replace(/^(x-api-key\s*:|authorization\s*:|bearer)\s*/i, '').replace(/^["'`]+|["'`]+$/g, '').replace(/\s+/g, '');
  const setRuntime = (c) => { runtime = { apiKey: cleanKey(c && c.apiKey), url: String((c && c.url) || '').trim() }; };

  const getConfig = () => {
    const apiKey = runtime.apiKey || cleanKey(process.env[envKey]);
    let base = (runtime.url || process.env[envUrl] || defaultUrl || '').trim().replace(/\/+$/, '');
    if (base && !/^https?:\/\//i.test(base)) base = 'https://' + base;
    if (base && !/\/api\/v1\/partner$/i.test(base)) base += '/api/v1/partner';
    return { apiKey, base, source: runtime.apiKey ? 'panel' : 'env' };
  };

  // Konfigurasi dianggap lengkap bila key DAN URL ada (gneseller tidak punya URL bawaan).
  const isConfigured = () => { const c = getConfig(); return !!(c.apiKey && c.base); };

  class PartnerError extends Error {
    constructor(code, message, { status = 0, transient = false } = {}) {
      super(message);
      this.name = 'PartnerError';
      this.provider = name;
      this.code = code;         // unauthorized | insufficient_balance | out_of_stock | invalid_product_or_duration | rate_limited | provider_error | timeout | network | not_configured | unknown
      this.status = status;
      this.transient = transient; // true = aman dicoba lagi nanti (idempotencyKey mencegah dobel)
    }
  }

  function toError(status, json, fallbackText) {
    const code = (json && json.error) || (status === 401 ? 'unauthorized' : status === 402 ? 'insufficient_balance' : status === 409 ? 'out_of_stock' : status === 429 ? 'rate_limited' : status === 502 ? 'provider_error' : 'unknown');
    const msg = (json && json.message) || (json && json.error) || (fallbackText || '').slice(0, 120) || `HTTP ${status}`;
    const transient = TRANSIENT_CODES.has(code) || status === 429 || status === 502 || status === 503 || status === 504 || (status >= 500 && code === 'unknown');
    return new PartnerError(code, msg, { status, transient });
  }

  async function call(path, opts) {
    const { apiKey, base } = getConfig();
    if (!apiKey || !base) throw new PartnerError('not_configured', `${label}: ${apiKey ? '' : 'API Key'}${!apiKey && !base ? ' dan ' : ''}${base ? '' : 'URL panel'} belum diisi (Admin → Pengaturan → Auto-Restock Provider).`);
    let r;
    try {
      r = await requestJson(base + path, { ...opts, headers: { 'X-API-Key': apiKey } });
    } catch (e) {
      throw new PartnerError(e.code === 'timeout' ? 'timeout' : 'network', e.message, { transient: true });
    }
    if (r.status >= 200 && r.status < 300) return r.json;
    throw toError(r.status, r.json, r.text);
  }

  // Durasi varian: label dulu (n + unit), `days` sebagai cadangan (selalu hari).
  function variantDuration(d) {
    const parsed = dur.parseDuration(d.label);
    if (parsed) return parsed;
    const days = Number(d.days) || 0;
    return { n: days, unit: 'day' };
  }

  // ── Katalog (cache 5 menit; stale dipakai kalau refresh gagal) ──
  let catalogCache = { at: 0, data: null };

  /** @returns {Promise<Array<{id,name,category,active,durations:Array<{id,label,n,unit,days,price,basePrice}>}>>} */
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
        durations: (Array.isArray(p.product_durations) ? p.product_durations : []).map((d) => {
          const lbl = String(d.label || d.id);
          const { n, unit } = variantDuration({ label: lbl, days: d.days });
          return {
            id: String(d.id),
            label: lbl,
            n, unit,
            days: unit === 'day' ? n : 0, // `days` hanya bermakna untuk varian HARI
            price: Number(d.price) || 0,
            basePrice: Number(d.base_price) || 0,
          };
        }),
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
   * @throws {PartnerError}
   */
  async function generateKey({ productId, durationId, idempotencyKey }) {
    if (!productId || !durationId) throw new PartnerError('invalid_product_or_duration', `Mapping ${label} belum lengkap (productId/durationId kosong).`);
    const json = await call('/generate-key', {
      method: 'POST',
      body: { productId: String(productId), durationId: String(durationId), idempotencyKey: String(idempotencyKey || '') || undefined },
      timeoutMs: GENERATE_TIMEOUT_MS,
    });
    const k = json && json.key;
    if (!k || !k.key_string) throw new PartnerError('provider_error', 'Respons generate-key tidak berisi key_string.', { transient: true });
    return { keyString: String(k.key_string), id: String(k.id || ''), price: Number(k.price) || 0 };
  }

  return {
    name, label, envKey, envUrl, idempotent: true,
    isConfigured, setRuntime, fetchCatalog, isListed, generateKey, PartnerError,
    _getConfig: getConfig, _resetCache: () => { catalogCache = { at: 0, data: null }; },
  };
}

module.exports = { createPartnerClient };
