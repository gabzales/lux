/**
 * reset-admin.js — Reset username & password admin LANGSUNG di Supabase.
 *
 * Kenapa script ini ada:
 *   Login admin membandingkan input dengan hash yang tersimpan di Supabase
 *   (tabel keyvalue_store → settings.json), BUKAN dengan env var. Env
 *   INITIAL_ADMIN_USERNAME / INITIAL_ADMIN_PASSWORD hanya dipakai SEKALI, saat
 *   settings masih kosong. Kalau app pernah jalan sebelum env diisi (mis. di
 *   lokal), password acak waktu itu sudah tersimpan, dan mengubah env belakangan
 *   tidak mengubah apa-apa.
 *
 * Pemakaian (paling aman — password diketik langsung, bukan lewat file .env):
 *   node reset-admin.js <username> "<password>"
 *
 * Atau tanpa argumen → script akan menanyakan username & password.
 *
 * Yang dilakukan:  hanya mengubah adminUsername + adminPassword, dan
 * melepas lock sesi admin. Settings lain (kontak, banner, tema, dsb.) TIDAK disentuh.
 * Efeknya langsung berlaku — tidak perlu redeploy Vercel (asal SUPABASE_URL di
 * .env lokal sama dengan yang dipakai Vercel; script menampilkan project ref-nya).
 */

require('dotenv').config();
const readline = require('readline');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const URL = (process.env.SUPABASE_URL || '').trim();
const KEY = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

if (!URL || !KEY) {
  console.error('❌ SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY harus ada di .env lokal.');
  process.exit(1);
}

const ask = (q) => new Promise((resolve) => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question(q, (a) => { rl.close(); resolve(a); });
});

async function main() {
  let username = process.argv[2];
  let password = process.argv[3];
  if (!username) username = await ask('Username admin baru : ');
  if (!password) password = await ask('Password admin baru : ');

  username = String(username || '').trim();
  password = String(password || '');

  if (!username) { console.error('❌ Username kosong.'); process.exit(1); }
  if (password.length < 8) { console.error('❌ Password minimal 8 karakter.'); process.exit(1); }

  const ref = URL.replace('https://', '').split('.')[0];
  console.log(`\n🔗 Supabase project : ${ref}   ← HARUS sama dengan project yang dipakai Vercel`);
  console.log(`👤 Username          : ${username}  (${username.length} karakter)`);
  console.log(`🔑 Password          : ${password.length} karakter (tidak ditampilkan)`);

  const supabase = createClient(URL, KEY, { auth: { persistSession: false } });

  const { data: row, error: readErr } = await supabase
    .from('keyvalue_store').select('value').eq('key', 'settings.json').maybeSingle();
  if (readErr) {
    console.error('❌ Gagal baca Supabase:', readErr.message || readErr.code || '(project paused / tabel belum dibuat?)');
    process.exit(1);
  }
  const current = (row && row.value && typeof row.value === 'object') ? row.value : {};
  console.log(`📋 Username tersimpan sebelumnya: ${current.adminUsername ? `"${current.adminUsername}"` : '(belum ada)'}`);

  const next = {
    ...current,
    adminUsername: username,
    adminPassword: bcrypt.hashSync(password, 12),
  };

  const { error: writeErr } = await supabase
    .from('keyvalue_store').upsert({ key: 'settings.json', value: next }, { onConflict: 'key' });
  if (writeErr) { console.error('❌ Gagal simpan:', writeErr.message); process.exit(1); }

  // Lepas lock sesi admin supaya tidak muncul "panel dipakai perangkat lain"
  await supabase.from('keyvalue_store').upsert({ key: 'admin-lock.json', value: {} }, { onConflict: 'key' });

  // Verifikasi dengan membaca ulang dari database (bukan percaya variabel lokal)
  const { data: check } = await supabase
    .from('keyvalue_store').select('value').eq('key', 'settings.json').maybeSingle();
  const saved = check && check.value;
  const ok = !!saved
    && saved.adminUsername === username
    && bcrypt.compareSync(password, saved.adminPassword || '');

  if (!ok) { console.error('❌ Verifikasi GAGAL — data di Supabase tidak cocok. Coba jalankan ulang.'); process.exit(1); }

  console.log('\n✅ BERHASIL & terverifikasi dari database.');
  console.log('   Login di:  /lx-secure-panel-7k   (langsung berlaku, tidak perlu redeploy)');
  console.log('   Tips: kalau password mengandung # $ atau spasi, kutip saat mengetik di terminal: "pass#word"\n');
}

main().catch((e) => { console.error('Fatal:', e.message); process.exit(1); });
