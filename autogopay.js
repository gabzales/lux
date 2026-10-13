/**
 * autogopay.js — Pembayaran QRIS via AutoGopay (https://autogopay.net).
 *
 *   Buat    : POST {BASE}/api/v1/payment/create   body { amount, reference, description, customer_name, callback_url }
 *             201 -> { success:true, data:{ invoice, reference, amount, qris_string, qr_image, payment_url, status, expired_at } }
 *   Status  : GET  {BASE}/api/v1/payment/status/{reference}   -> data.status: pending|success|failed|expired
 *   Batal   : POST {BASE}/api/v1/payment/cancel   body { reference | invoice }
 *   Auth    : header X-API-Key: iak_xxx
 *   Webhook : POST ke callback_url, body { event, invoice, reference, amount, status, paid_at, timestamp, signature }
 *             signature = HMAC-SHA256(Webhook Secret, JSON payload TANPA field signature)
 *
 * Environment:
 *   AUTOGOPAY_API_KEY         wajib
 *   AUTOGOPAY_WEBHOOK_SECRET  disarankan (untuk verifikasi signature webhook)
 *   AUTOGOPAY_BASE_URL        opsional (default https://autogopay.net)
 *   APP_URL                   URL publik toko (untuk callback_url)
 *
 * Keamanan: isi webhook TIDAK pernah dipercaya begitu saja. Bila signature cocok → dipakai;
 * bila tidak cocok / secret belum diisi → status dikonfirmasi ulang lewat endpoint status (pakai API key).
 */
const crypto = require('crypto');
const { requestJson } = require('./httpjson');

const DEFAULT_BASE = 'https://autogopay.net';
const MIN_AMOUNT = 1000;
const REF_RE = /^[A-Za-z0-9_-]{1,50}$/;

// Kredensial dari Admin → Settings (tersimpan di settings.autogopay); env dipakai bila kosong.
let runtime = { apiKey: '', webhookSecret: '' };
const setRuntime = (c) => { runtime = { apiKey: String((c && c.apiKey) || '').trim(), webhookSecret: String((c && c.webhookSecret) || '').trim() }; };
const mask = (v) => (v ? '••••' + String(v).slice(-4) : '');

const getConfig = () => ({
  apiKey: runtime.apiKey || (process.env.AUTOGOPAY_API_KEY || '').trim(),
  webhookSecret: runtime.webhookSecret || (process.env.AUTOGOPAY_WEBHOOK_SECRET || '').trim(),
  baseUrl: (process.env.AUTOGOPAY_BASE_URL || DEFAULT_BASE).trim().replace(/\/+$/, ''),
});
const isConfigured = () => !!getConfig().apiKey;
const makeOrderId = (prefix = 'LX') => `${prefix}-${Date.now().toString(36).toUpperCase()}${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

class AutogopayError extends Error {
  constructor(code, message, status = 0) { super(message); this.name = 'AutogopayError'; this.code = code; this.status = status; }
}

// "2026-06-21 15:00:00" (tanpa zona) = WIB; format ISO dibiarkan.
function toISO(v) {
  if (v == null || v === '') return null;
  let s = String(v).trim();
  if (/^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d$/.test(s)) s = s.replace(' ', 'T') + '+07:00';
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

async function call(path, { method = 'GET', body } = {}) {
  const { apiKey, baseUrl } = getConfig();
  if (!apiKey) throw new AutogopayError('not_configured', 'AUTOGOPAY_API_KEY belum diisi di environment.');
  try {
    return await requestJson(baseUrl + path, { method, headers: { 'X-API-Key': apiKey }, body, timeoutMs: 15000 });
  } catch (e) {
    throw new AutogopayError(e.code === 'timeout' ? 'timeout' : 'network', e.message);
  }
}
const errMsg = (r) => (r.json && (r.json.message || r.json.error)) || `HTTP ${r.status}`;

async function createQris({ orderId, amount, callbackUrl, description, customerName }) {
  if (!REF_RE.test(String(orderId))) throw new AutogopayError('bad_order_id', 'reference tidak valid untuk AutoGopay.');
  const amt = Math.round(Number(amount));
  if (!(amt >= MIN_AMOUNT)) throw new AutogopayError('amount_too_small', `Minimal pembayaran QRIS Rp ${MIN_AMOUNT.toLocaleString('id-ID')}.`);
  const body = { amount: amt, reference: orderId };
  if (description) body.description = String(description).slice(0, 120);
  if (customerName) body.customer_name = String(customerName).slice(0, 60);
  if (callbackUrl) body.callback_url = callbackUrl;
  const r = await call('/api/v1/payment/create', { method: 'POST', body });
  const d = r.json && r.json.data;
  if ((r.status === 200 || r.status === 201) && r.json && r.json.success && d && d.qris_string) {
    return {
      qrString: String(d.qris_string),
      invoice: d.invoice || null,
      amount: Number(d.amount) || amt,
      expiresAt: toISO(d.expired_at),
    };
  }
  throw new AutogopayError(r.status === 401 ? 'unauthorized' : (r.status === 403 ? 'forbidden' : 'rejected'), String(errMsg(r)), r.status);
}

/** @returns {Promise<{status:string, amount:number|null, invoice:string|null}>} status huruf besar: PENDING|SUCCESS|FAILED|EXPIRED */
async function getStatus(reference) {
  const r = await call('/api/v1/payment/status/' + encodeURIComponent(reference));
  const d = r.json && r.json.data;
  if (r.status === 200 && r.json && r.json.success && d) {
    return { status: String(d.status || '').toUpperCase(), amount: d.amount != null ? Number(d.amount) : null, invoice: d.invoice || null };
  }
  throw new AutogopayError(r.status === 404 ? 'not_found' : 'rejected', String(errMsg(r)), r.status);
}

function hmacHex(secret, str) { return crypto.createHmac('sha256', secret).update(str).digest('hex'); }
function safeEq(a, b) {
  const x = Buffer.from(String(a).toLowerCase()), y = Buffer.from(String(b).toLowerCase());
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/**
 * Verifikasi signature webhook. Cara serialisasi di sisi AutoGopay tidak dijelaskan dokumen,
 * jadi dicoba beberapa kandidat yang lazim (urutan field asli, JSON PHP dengan "\/" & \uXXXX, body mentah tanpa signature).
 */
function verifyWebhook(rawBody, payload) {
  const { webhookSecret } = getConfig();
  if (!webhookSecret || !payload || typeof payload.signature !== 'string') return false;
  const sig = payload.signature.trim();
  if (!/^[0-9a-f]{64}$/i.test(sig)) return false;
  const copy = { ...payload }; delete copy.signature;
  const plain = JSON.stringify(copy);
  const phpEsc = plain.replace(/\//g, '\\/').replace(/[\u0080-\uffff]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  const cands = [plain, phpEsc];
  if (typeof rawBody === 'string') {
    cands.push(rawBody.replace(/,\s*"signature"\s*:\s*"[^"]*"/, '').replace(/"signature"\s*:\s*"[^"]*"\s*,?\s*/, ''));
  }
  return cands.some((c) => safeEq(hmacHex(webhookSecret, c), sig));
}

function isAmountEnough(amount, expectedPrice) {
  const n = Number(amount);
  if (!Number.isFinite(n) || n <= 0) return true;
  return n >= Number(expectedPrice);
}

module.exports = { setRuntime, mask, isConfigured, getConfig, createQris, getStatus, verifyWebhook, isAmountEnough, makeOrderId, AutogopayError, MIN_AMOUNT };
