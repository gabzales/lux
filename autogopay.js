/**
 * autogopay.js — Pembayaran QRIS dinamis GoPay via AutoGoPay (https://autogopay.site/docs).
 *
 *   Base URL : https://v1-gateway.autogopay.site
 *   Auth     : header  Authorization: Bearer <API_KEY>
 *   Buat     : POST /qris/generate   body { amount }            (1 – 10.000.000)
 *              -> { success, data:{ transaction_id, order_id, amount, transaction_status, qr_string,
 *                                   qr_url, checkout_url, transaction_time, expiry_time } }
 *   Status   : POST /qris/status     body { transaction_id }    -> pending | settlement | expire | cancel
 *   Batal    : POST /qris/cancel     body { transaction_id }
 *   Webhook  : POST ke callback URL yang diatur di DASHBOARD AutoGoPay (bukan per-request)
 *              header  X-Signature = HMAC-SHA256(rawBody, secret = API key)
 *              body    { event:'transaction.received', timestamp,
 *                        transaction:{ transaction_id, order_id, amount, status:'PAID', payment_method, paid_at } }
 *
 * Environment:
 *   AUTOGOPAY_API_KEY    wajib (juga dipakai sebagai secret verifikasi signature webhook)
 *   AUTOGOPAY_BASE_URL   opsional (default https://v1-gateway.autogopay.site)
 *   APP_URL              URL publik toko (hanya untuk menampilkan Webhook URL di admin)
 *
 * Catatan: AutoGoPay tidak menerima "reference" dari kita — transaksi dikenali lewat transaction_id
 * miliknya. transaction_id itulah yang disimpan sebagai `orderId` di transactions.json.
 *
 * Keamanan: isi webhook tidak pernah dipercaya begitu saja. Signature cocok → dipakai; tidak cocok →
 * status dikonfirmasi ulang lewat endpoint status (pakai API key).
 */
const crypto = require('crypto');
const { requestJson } = require('./httpjson');

const DEFAULT_BASE = 'https://v1-gateway.autogopay.site';
const MIN_AMOUNT = 1;
const MAX_AMOUNT = 10000000;
// Nominal tes koneksi di admin (cukup kecil, dibatalkan langsung).
const TEST_AMOUNT = 1000;

// Kredensial dari Admin → Settings (tersimpan di settings.autogopay); env dipakai bila kosong.
let runtime = { apiKey: '' };
// Bersihkan salah tempel: spasi/enter, tanda kutip, awalan "Bearer " / "Authorization:".
const cleanKey = (v) => String(v || '').trim().replace(/^(x-api-key\s*:|authorization\s*:|bearer)\s*/i, '').replace(/^["'`]+|["'`]+$/g, '').replace(/\s+/g, '');
const setRuntime = (c) => { runtime = { apiKey: cleanKey(c && c.apiKey) }; };
const mask = (v) => (v ? '••••' + String(v).slice(-4) : '');

const getConfig = () => ({
  apiKey: runtime.apiKey || cleanKey(process.env.AUTOGOPAY_API_KEY),
  source: runtime.apiKey ? 'panel' : 'env',
  baseUrl: (process.env.AUTOGOPAY_BASE_URL || DEFAULT_BASE).trim().replace(/\/+$/, ''),
});
const isConfigured = () => !!getConfig().apiKey;

class AutogopayError extends Error {
  constructor(code, message, status = 0) { super(message); this.name = 'AutogopayError'; this.code = code; this.status = status; }
}

// "2026-03-27 20:49:00" (tanpa zona) = WIB; format ISO dibiarkan.
function toISO(v) {
  if (v == null || v === '') return null;
  let s = String(v).trim();
  if (/^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d$/.test(s)) s = s.replace(' ', 'T') + '+07:00';
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

async function call(path, { method = 'POST', body } = {}) {
  const { apiKey, baseUrl } = getConfig();
  if (!apiKey) throw new AutogopayError('not_configured', 'AUTOGOPAY_API_KEY belum diisi.');
  try {
    return await requestJson(baseUrl + path, { method, headers: { Authorization: 'Bearer ' + apiKey }, body, timeoutMs: 15000 });
  } catch (e) {
    throw new AutogopayError(e.code === 'timeout' ? 'timeout' : 'network', e.message);
  }
}
const errMsg = (r) => (r.json && (r.json.message || r.json.error)) || `HTTP ${r.status}`;

/**
 * Normalisasi status AutoGoPay → PENDING | SUCCESS | EXPIRED | FAILED (huruf besar, dipakai server.js).
 * Mencakup nilai status API (pending/settlement/expire/cancel) dan status webhook (PAID).
 */
function mapStatus(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (['settlement', 'paid', 'success', 'settled', 'completed', 'capture'].includes(s)) return 'SUCCESS';
  if (['expire', 'expired'].includes(s)) return 'EXPIRED';
  if (['cancel', 'canceled', 'cancelled', 'failed', 'deny', 'failure'].includes(s)) return 'FAILED';
  if (s === 'pending') return 'PENDING';
  return s ? s.toUpperCase() : '';
}

/** @returns {Promise<{transactionId:string, providerOrderId:string|null, qrString:string, checkoutUrl:string|null, amount:number, expiresAt:string|null}>} */
async function createQris({ amount }) {
  const amt = Math.round(Number(amount));
  if (!(amt >= MIN_AMOUNT)) throw new AutogopayError('amount_too_small', 'Nominal pembayaran tidak valid.');
  if (amt > MAX_AMOUNT) throw new AutogopayError('amount_too_large', `Maksimal pembayaran QRIS Rp ${MAX_AMOUNT.toLocaleString('id-ID')}.`);
  const r = await call('/qris/generate', { method: 'POST', body: { amount: amt } });
  const d = r.json && r.json.data;
  if ((r.status === 200 || r.status === 201) && r.json && r.json.success && d && d.qr_string && d.transaction_id) {
    return {
      transactionId: String(d.transaction_id),
      providerOrderId: d.order_id ? String(d.order_id) : null,
      qrString: String(d.qr_string),
      checkoutUrl: d.checkout_url || null,
      amount: Number(d.amount) || amt,
      expiresAt: toISO(d.expiry_time),
    };
  }
  throw new AutogopayError(r.status === 401 ? 'unauthorized' : (r.status === 403 ? 'forbidden' : 'rejected'), String(errMsg(r)), r.status);
}

/** @returns {Promise<{status:string, amount:number|null}>} status: PENDING|SUCCESS|EXPIRED|FAILED */
async function getStatus(transactionId) {
  const r = await call('/qris/status', { method: 'POST', body: { transaction_id: String(transactionId) } });
  const j = r.json;
  if (r.status === 200 && j && j.success !== false) {
    // Bentuk respons status tidak dijelaskan dokumen → baca dari beberapa lokasi lazim.
    const d = (j.data && typeof j.data === 'object') ? j.data : j;
    const raw = d.transaction_status || d.status || d.payment_status || j.transaction_status || j.status;
    const status = mapStatus(raw);
    if (status) return { status, amount: d.amount != null ? Number(d.amount) : null };
  }
  throw new AutogopayError(r.status === 404 ? 'not_found' : 'rejected', String(errMsg(r)), r.status);
}

async function cancelQris(transactionId) {
  const r = await call('/qris/cancel', { method: 'POST', body: { transaction_id: String(transactionId) } });
  return r.status >= 200 && r.status < 300 && !(r.json && r.json.success === false);
}

function safeEq(a, b) {
  const x = Buffer.from(String(a).toLowerCase()), y = Buffer.from(String(b).toLowerCase());
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/** Verifikasi header X-Signature = HMAC-SHA256(rawBody, API key). Wajib memakai body mentah persis seperti diterima. */
function verifyWebhook(rawBody, signatureHeader) {
  const { apiKey } = getConfig();
  if (!apiKey || typeof rawBody !== 'string' || !rawBody || typeof signatureHeader !== 'string') return false;
  const sig = signatureHeader.trim().replace(/^sha256=/i, '');
  if (!/^[0-9a-f]{64}$/i.test(sig)) return false;
  return safeEq(crypto.createHmac('sha256', apiKey).update(rawBody).digest('hex'), sig);
}

function isAmountEnough(amount, expectedPrice) {
  const n = Number(amount);
  if (!Number.isFinite(n) || n <= 0) return true;
  return n >= Number(expectedPrice);
}

module.exports = { setRuntime, mask, isConfigured, getConfig, createQris, getStatus, cancelQris, mapStatus, verifyWebhook, isAmountEnough, AutogopayError, MIN_AMOUNT, MAX_AMOUNT, TEST_AMOUNT };
