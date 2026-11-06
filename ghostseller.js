/**
 * ghostseller.js — Klien Ghostseller Partner API v1.
 * Logika ada di partnerapi.js (dipakai bersama gneseller.js); file ini hanya menentukan env & URL bawaan.
 *
 *   GHOSTSELLER_API_KEY   wajib
 *   GHOSTSELLER_API_URL   opsional, default https://www.ghostseller.my.id
 *                         (boleh domain saja, mis. https://xxx.vercel.app, atau URL lengkap .../api/v1/partner)
 */
const { createPartnerClient } = require('./partnerapi');

module.exports = createPartnerClient({
  name: 'ghostseller',
  label: 'Ghostseller',
  envKey: 'GHOSTSELLER_API_KEY',
  envUrl: 'GHOSTSELLER_API_URL',
  defaultUrl: 'https://www.ghostseller.my.id',
});
