/**
 * durations.js — Parsing & format durasi produk: HARI (default, kompatibel dengan
 * data lama) dan JAM (varian baru).
 *
 * Kenapa perlu "token":
 *   Stok key bisa diberi tag durasi, mis. "ABC-123:3" (key khusus 3 hari).
 *   Dulu tag hanya angka hari. Kalau varian jam ikut pakai angka saja, "3 jam"
 *   dan "3 hari" bentrok (keduanya "3") dan pembeli 3 jam bisa kebagian key 3 hari.
 *   Jadi tiap durasi punya TOKEN unik:   3 hari -> "3"   |   3 jam -> "3h"
 *   (hari memakai angka polos supaya semua tag lama tetap valid).
 */

const UNIT_RE = /(\d+)\s*(JAM|HOURS?|HRS?|H|DAYS?|HARI|D)\b/gi;

const normUnit = (u) => (/^(JAM|HOURS?|HRS?|H)$/i.test(u) ? 'hour' : 'day');

/** "DRIP 3 HOURS" -> {n:3, unit:'hour'};  "DRIP 7 DAYS" -> {n:7, unit:'day'};  tanpa satuan -> null */
function parseDuration(label) {
  const s = String(label || '');
  let m, last = null;
  UNIT_RE.lastIndex = 0;
  while ((m = UNIT_RE.exec(s)) !== null) last = m; // durasi ada di akhir label → ambil kemunculan terakhir
  if (!last) return null;
  const n = parseInt(last[1], 10);
  if (!(n > 0)) return null;
  return { n, unit: normUnit(last[2]) };
}

/** Token unik: hari -> "3", jam -> "3h" */
const toToken = (n, unit) => (n > 0 ? `${parseInt(n, 10)}${unit === 'hour' ? 'h' : ''}` : null);

/** Token dari transaksi (data lama hanya punya selectedDays -> dianggap hari) */
const txToken = (tx) => (tx ? toToken(tx.selectedDays, tx.selectedUnit) : null);

/** "3 Jam" / "7 Hari" untuk tampilan */
const displayLabel = (n, unit) => `${n} ${unit === 'hour' ? 'Jam' : 'Hari'}`;

/** Label item katalog: "NAMA 3 HOURS" / "NAMA 7 DAYS" (gaya lama dipertahankan) */
const itemLabel = (name, n, unit) => `${String(name || 'PRODUK').toUpperCase()} ${n} ${unit === 'hour' ? 'HOURS' : 'DAYS'}`;

/** Urutan tampil: jam dulu (kecil->besar), lalu hari. */
const totalHours = (n, unit) => (unit === 'hour' ? n : n * 24);

/**
 * Pisahkan "KEY:TAG" dari baris stok.
 *   "ABC-1:3"   -> {key:'ABC-1', token:'3'}      (3 hari)
 *   "ABC-1:3d"  -> {key:'ABC-1', token:'3'}
 *   "ABC-1:3h"  -> {key:'ABC-1', token:'3h'}     (3 jam)
 *   "user:pass" -> {key:'user:pass', token:null}  (bukan tag durasi -> key generik utuh)
 */
function splitKeyTag(raw) {
  const s = String(raw == null ? '' : raw);
  const i = s.lastIndexOf(':');
  if (i > 0) {
    const m = s.slice(i + 1).trim().match(/^(\d+)\s*([dh])?$/i);
    if (m && parseInt(m[1], 10) > 0) {
      return { key: s.slice(0, i), token: toToken(parseInt(m[1], 10), (m[2] || '').toLowerCase() === 'h' ? 'hour' : 'day') };
    }
  }
  return { key: s, token: null };
}

module.exports = { parseDuration, toToken, txToken, displayLabel, itemLabel, totalHours, splitKeyTag };
