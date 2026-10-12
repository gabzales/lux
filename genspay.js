/**
 * genspay.js — Pembayaran QRIS via GensPay (kontrak diambil dari implementasi di project Ghostseller).
 *
 *   Buat transaksi : POST {BASE}/transaction/create
 *                    header X-API-Key, body { amount, order_id, payment_method:"qris", callback_url }
 *                    201 -> { success:true, data:{ qr_string, amount, fee, net_amount, expiry_time } }
 *                    error -> { error:"pesan" } (400/401/409/503) — tanpa field success
 *   order_id       : hanya huruf/angka/-/_ , maksimal 50 karakter
 *   Minimal nominal: Rp 1.000
 *   Webhook        : header X-GensPay-Signature = hex( SHA256( rawBody + API_KEY ) )   ← SHA256 biasa, BUKAN HMAC
 *                    body { event:"transaction.updated", data:{ order_id, status:"SUCCESS"|"EXPIRED"|"FAILED", amount, fee, net_amount } }
 *                    GensPay mengulang sampai 5x bila respons bukan 2xx.
 *
 * Konfigurasi HANYA lewat environment:
 *   GENSPAY_API_KEY    wajib
 *   GENSPAY_BASE_URL   opsional (default https://genspay.my.id/api/v1)
 *   APP_URL            URL publik toko, mis. https://luxzco.vercel.app  (dipakai untuk callback_url)
 */
const crypto = require('crypto');
const { requestJson } = require('./httpjson');

const DEFAULT_BASE = 'https://genspay.my.id/api/v1';
const MIN_AMOUNT = 1000;
const ORDER_ID_RE = /^[A-Za-z0-9_-]{1,50}$/;

const getConfig = () => ({
  apiKey: (process.env.GENSPAY_API_KEY || '').trim(),
  baseUrl: (process.env.GENSPAY_BASE_URL || DEFAULT_BASE).trim().replace(/\/+$/, ''),
  appUrl: (process.env.APP_URL || '').trim().replace(/\/+$/, ''),
});

const isConfigured = () => !!getConfig().apiKey;

/** ID order aman untuk GensPay: LX-<waktu base36><6 hex acak>  (≈ 20 karakter) */
const makeOrderId = (prefix = 'LX') => `${prefix}-${Date.now().toString(36).toUpperCase()}${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

class GenspayError extends Error {
  constructor(code, message, status = 0) { super(message); this.name = 'GenspayError'; this.code = code; this.status = status; }
}

/**
 * @param {{orderId:string, amount:number, callbackUrl:string}} p
 * @returns {Promise<{qrString:string, amount:number, fee:number, netAmount:number|null, expiresAt:string|number|null}>}
 */
async function createQris({ orderId, amount, callbackUrl }) {
  const { apiKey, baseUrl } = getConfig();
  if (!apiKey) throw new GenspayError('not_configured', 'GENSPAY_API_KEY belum diisi di environment.');
  if (!ORDER_ID_RE.test(String(orderId))) throw new GenspayError('bad_order_id', 'order_id tidak valid untuk GensPay.');
  const amt = Math.round(Number(amount));
  if (!(amt >= MIN_AMOUNT)) throw new GenspayError('amount_too_small', `Minimal pembayaran QRIS GensPay Rp ${MIN_AMOUNT.toLocaleString('id-ID')}.`);

  let r;
  try {
    r = await requestJson(baseUrl + '/transaction/create', {
      method: 'POST',
      headers: { 'X-API-Key': apiKey },
      body: { amount: amt, order_id: orderId, payment_method: 'qris', callback_url: callbackUrl },
      timeoutMs: 15000,
    });
  } catch (e) {
    throw new GenspayError(e.code === 'timeout' ? 'timeout' : 'network', e.message);
  }

  const d = r.json && r.json.data;
  if (r.status === 201 && r.json && r.json.success && d && d.qr_string) {
    return {
      qrString: String(d.qr_string),
      amount: Number(d.amount) || amt,
      fee: Number(d.fee) || 0,
      netAmount: d.net_amount != null ? Number(d.net_amount) : null,
      expiresAt: d.expiry_time || null,
    };
  }
  const msg = (r.json && (r.json.error || r.json.message)) || `HTTP ${r.status}`;
  throw new GenspayError(r.status === 401 ? 'unauthorized' : 'rejected', String(msg), r.status);
}

/** Verifikasi X-GensPay-Signature: SHA256(rawBody + apiKey), dibandingkan timing-safe. */
function verifySignature(rawBody, signatureHeader) {
  const { apiKey } = getConfig();
  if (!apiKey || typeof rawBody !== 'string' || typeof signatureHeader !== 'string') return false;
  const provided = signatureHeader.trim();
  const expected = crypto.createHash('sha256').update(rawBody + apiKey).digest();
  if (!/^[0-9a-f]+$/i.test(provided) || provided.length !== expected.length * 2) return false;
  return crypto.timingSafeEqual(expected, Buffer.from(provided, 'hex'));
}

/**
 * Apakah nominal yang dibayar cukup untuk pesanan?
 * Kebijakan: pembeli membayar `amount` (sudah termasuk biaya bila GensPay menambahkannya);
 * pesanan dianggap lunas bila nilai yang tercatat >= harga pesanan. Kurang bayar ditolak.
 * (Ghostseller membandingkan net_amount; di sini memakai nilai terbesar yang tersedia supaya
 *  biaya admin gateway tidak membuat pembayaran sah ditolak. Pembayaran kurang tetap ditolak.)
 */
function isAmountEnough(data, expectedPrice) {
  const vals = [data && data.amount, data && data.net_amount].map(Number).filter((n) => Number.isFinite(n) && n > 0);
  if (!vals.length) return true; // gateway tidak mengirim nominal; signature sudah memvalidasi event
  return Math.max(...vals) >= Number(expectedPrice);
}

module.exports = { isConfigured, getConfig, createQris, verifySignature, isAmountEnough, makeOrderId, GenspayError, MIN_AMOUNT };
