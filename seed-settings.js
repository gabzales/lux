/**
 * seed-settings.js — Push settings + logo ke Supabase
 * 
 * CARA PAKAI:
 *   node seed-settings.js
 * 
 * Jalankan SEKALI setelah deploy atau setiap kali ganti credentials.
 * Script ini akan:
 *   1. Upload logo ke Supabase Storage → dapat URL publik
 *   2. Overwrite settings di Supabase dengan kredensial & konfigurasi terbaru
 */

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY; // bukan anon key — RLS sekarang blokir anon

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ Set SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY di file .env dulu!');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { persistSession: false } });

// ── KREDENSIAL DIAMBIL DARI .env, JANGAN DI-HARDCODE DI SINI ──
// Isi ADMIN_USERNAME dan ADMIN_PASSWORD di file .env lokal kamu
// (file .env tidak ikut ke-push ke GitHub karena ada di .gitignore).
// .trim() username (spasi tak kasat mata). Password JANGAN di-trim.
// CATATAN: dotenv memotong value di tanda # kalau tidak dikutip → di .env tulis
//   SEED_ADMIN_PASSWORD="pass#word"   (pakai kutip). Atau pakai: node reset-admin.js
const ADMIN_USERNAME = (process.env.SEED_ADMIN_USERNAME || '').trim();
const ADMIN_PASSWORD = process.env.SEED_ADMIN_PASSWORD;
if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
  console.error('❌ Set SEED_ADMIN_USERNAME dan SEED_ADMIN_PASSWORD di file .env lokal dulu (jangan di-hardcode di script ini).');
  process.exit(1);
}
const SITE_NAME      = 'Luxzco';
const WA_NUMBER      = '';
const WA_CHANNEL     = '';
const APK_CHANNEL    = '';
const TIKTOK_USER    = '';
// ─────────────────────────────────────────────────────────


async function main() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  Luxzco — Seed Settings ke Supabase');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  // 1. Logo = wordmark statis di public/uploads (tidak perlu upload ke storage)
  const logoUrl = '/uploads/logo-luxzco-text.png';

  // 2. Ambil settings existing
  const { data: existing } = await supabase
    .from('keyvalue_store').select('value').eq('key', 'settings.json').single();
  const current = (existing?.value && typeof existing.value === 'object') ? existing.value : {};
  console.log('📋 Existing adminUsername:', current.adminUsername || '(none)');

  // 3. Build settings baru
  const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  const newSettings = {
    ...current,                          // pertahankan data yang ada (produk, pakasir key, dll)
    siteName: SITE_NAME,
    gamePanelName: SITE_NAME,
    about: `${SITE_NAME} adalah Premium Gaming Marketplace #1 di Indonesia — Top Up Game, APK Premium, Panel, dan Digital Product dengan proses cepat & aman.`,
    marqueeText: 'Bayar mudah via QRIS|Pesanan dikonfirmasi langsung oleh admin|Key tampil di halaman Cek Pesanan|Stok diperbarui langsung oleh admin',
    // Pertahankan kontak yang sudah diisi lewat Admin Panel; konstanta di atas hanya
    // dipakai kalau field itu memang masih kosong (dulu: selalu menimpa jadi kosong).
    contact: {
      ...(current.contact || {}),
      whatsapp:   (current.contact && current.contact.whatsapp)   || WA_NUMBER,
      telegram:   (current.contact && current.contact.telegram)   || WA_CHANNEL,
      tiktok:     (current.contact && current.contact.tiktok)     || TIKTOK_USER,
      apkChannel: (current.contact && current.contact.apkChannel) || APK_CHANNEL,
      email:      (current.contact && current.contact.email)      || ''
    },
    adminUsername: ADMIN_USERNAME,
    adminPassword: adminHash,
    adminLockEnabled: current.adminLockEnabled !== undefined ? current.adminLockEnabled : true,
    logoUrl,
    faviconUrl: '/uploads/favicon-lx.png',
    theme: current.theme || {
      primaryColor: '#06b6d4',
      secondaryColor: '#22d3ee',
      accentColor: '#67e8f9',
      backgroundColor: '#09090b',
      cardBackground: '#111113',
      borderColor: 'rgba(79,123,255,.18)',
      glowColor: 'rgba(79,123,255,0.55)'
    },
    categories: current.categories || ['freefire','mlbb','pubgm','sertifikat'],
    categoryLabels: current.categoryLabels || {
      freefire:'FREE FIRE', mlbb:'MOBILE LEGENDS', pubgm:'PUBG MOBILE', sertifikat:'SERTIFIKAT'
    },
    resellerEnabled: true,
    resellerPrice: current.resellerPrice ?? 50000,
    resellerDiscount: current.resellerDiscount ?? 20,
    resellerNote: current.resellerNote || 'Dapatkan diskon eksklusif untuk semua produk!',
    popularProductIds: current.popularProductIds || [],
    pakasir: current.pakasir || { apiKey:'', project:'', mode:'production' },
    banners: (process.env.SEED_RESET_BANNERS === '1' || !current.banners?.length) ? [
      {
        id: 'banner-default-1',
        imageUrl: '/uploads/banners/banner-1.jpg',
        title: '',
        subtitle: '',
        link: '/products',
        active: true,
        createdAt: new Date().toISOString()
      },
      {
        id: 'banner-default-2',
        imageUrl: '/uploads/banners/banner-2.jpg',
        title: '',
        subtitle: '',
        link: '/products',
        active: true,
        createdAt: new Date().toISOString()
      }
    ] : current.banners,
  };

  // 4. Upsert ke Supabase
  const { error } = await supabase
    .from('keyvalue_store')
    .upsert({ key: 'settings.json', value: newSettings }, { onConflict: 'key' });

  if (error) {
    console.error('❌ Gagal simpan ke Supabase:', error.message);
    process.exit(1);
  }

  // 5. Verifikasi
  const { data: v } = await supabase
    .from('keyvalue_store').select('value').eq('key', 'settings.json').single();
  const saved = v?.value;

  console.log('\n✅ BERHASIL disimpan ke Supabase!');
  console.log('┌─────────────────────────────────────────');
  console.log('│ siteName     :', saved?.siteName);
  console.log('│ adminUsername:', saved?.adminUsername);
  console.log('│ logoUrl      :', saved?.logoUrl);
  console.log('│ whatsapp     :', saved?.contact?.whatsapp);
  console.log('│ banners      :', saved?.banners?.length ?? 0, 'item(s)');
  console.log('│ hash verify  :', bcrypt.compareSync(ADMIN_PASSWORD, saved?.adminPassword || '') ? '✅ OK' : '❌ GAGAL');
  console.log('└─────────────────────────────────────────');
  console.log(`\n🔐 Login admin: username=${ADMIN_USERNAME}  password=(dari .env, tidak ditampilkan)`);
  console.log('🌐 Deploy ulang Vercel agar settings baru aktif.\n');
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
