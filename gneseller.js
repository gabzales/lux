/**
 * gneseller.js — Provider auto-restock Gneseller (Partner API v1, kontrak sama dengan Ghostseller).
 *
 * Konfigurasi HANYA lewat environment (tidak pernah disimpan di database / dikirim ke browser):
 *   GNESELLER_API_KEY   wajib   (format gs_partner_..., dari admin Gneseller)
 *   GNESELLER_API_URL   wajib   domain panel, mis. https://xxx.vercel.app  (boleh juga URL lengkap .../api/v1/partner)
 *
 * Tidak ada URL bawaan: tiap deployment Gneseller punya domain sendiri.
 */
const { createPartnerClient } = require('./partnerapi');

module.exports = createPartnerClient({
  name: 'gneseller',
  label: 'Gneseller',
  envKey: 'GNESELLER_API_KEY',
  envUrl: 'GNESELLER_API_URL',
  defaultUrl: '',
});
