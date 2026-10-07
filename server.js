const express = require('express');
const cookieSession = require('cookie-session');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const https = require('https');
const multer = require('multer');
const crypto = require('crypto');

// Load .env FIRST before anything reads process.env
require('dotenv').config();

// Production warning tapi JANGAN exit — Vercel kadat lambat inject env
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET tidak di-set. Menggunakan fallback. Segera set di Vercel env vars!');
}

// Load DB module AFTER dotenv so env vars are available
const db = require('./supabase');
const dur = require('./durations');
const ghostseller = require('./ghostseller');
const dripstore = require('./dripstore');
const genspay = require('./genspay');
// Penanda versi: bisa dicek di /__build dan di Admin → Pengaturan, supaya jelas build mana yang sedang jalan.
const APP_VERSION = '2026-10-07 · hari/jam + redesign + GensPay + Drip Store + Ghostseller';

const app = express();
const PORT = process.env.PORT || 3000;

// Rate limiting untuk QR Code
const qrRateLimit = new Map();
const QR_RATE_LIMIT = 30;
const QR_RATE_WINDOW = 60000;

// Rate limiting untuk login (brute force protection)
const loginFailMap = new Map();
const LOGIN_MAX_FAIL = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 menit

const checkLoginBlocked = (ip) => {
  const rec = loginFailMap.get(ip);
  if (!rec) return { blocked: false };
  if (Date.now() > rec.resetAt) { loginFailMap.delete(ip); return { blocked: false }; }
  return { blocked: rec.count >= LOGIN_MAX_FAIL, wait: Math.ceil((rec.resetAt - Date.now()) / 60000) };
};

const recordLoginFail = (ip) => {
  const now = Date.now();
  const rec = loginFailMap.get(ip);
  if (!rec || now > rec.resetAt) loginFailMap.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
  else { rec.count++; loginFailMap.set(ip, rec); }
};

const clearLoginFail = (ip) => loginFailMap.delete(ip);

// Rate limiting untuk aktivasi key (cegah brute-force nebak kode key)
const activateKeyRateMap = new Map();
const ACTIVATE_KEY_MAX_FAIL = 8;
const ACTIVATE_KEY_WINDOW_MS = 15 * 60 * 1000; // 15 menit

const checkActivateKeyBlocked = (ip) => {
  const rec = activateKeyRateMap.get(ip);
  if (!rec) return { blocked: false };
  if (Date.now() > rec.resetAt) { activateKeyRateMap.delete(ip); return { blocked: false }; }
  return { blocked: rec.count >= ACTIVATE_KEY_MAX_FAIL, wait: Math.ceil((rec.resetAt - Date.now()) / 60000) };
};

const recordActivateKeyFail = (ip) => {
  const now = Date.now();
  const rec = activateKeyRateMap.get(ip);
  if (!rec || now > rec.resetAt) activateKeyRateMap.set(ip, { count: 1, resetAt: now + ACTIVATE_KEY_WINDOW_MS });
  else { rec.count++; activateKeyRateMap.set(ip, rec); }
};

// ── Cloudflare Turnstile verification ────────────────────────────────────────
async function verifyTurnstile(token) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) return true; // Turnstile tidak dikonfigurasi, skip verifikasi

  return new Promise((resolve) => {
    const body = JSON.stringify({
      secret,
      response: token,
    });

    const options = {
      hostname: 'challenges.cloudflare.com',
      path: '/turnstile/v0/siteverify',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.success === true);
        } catch {
          resolve(false);
        }
      });
    });

    req.on('error', () => resolve(false));
    req.write(body);
    req.end();
  });
}
// ─────────────────────────────────────────────────────────────────────────────

// Invoice rate limiting (cegah brute force order code enumeration)
const invoiceRateMap = new Map();
const INVOICE_RATE_LIMIT = 10;
const INVOICE_RATE_WINDOW = 5 * 60 * 1000;

const checkInvoiceRateLimit = (ip) => {
  const now = Date.now();
  const rec = invoiceRateMap.get(ip);
  if (!rec || now > rec.resetAt) {
    invoiceRateMap.set(ip, { count: 1, resetAt: now + INVOICE_RATE_WINDOW });
    return true;
  }
  if (rec.count >= INVOICE_RATE_LIMIT) return false;
  rec.count++;
  return true;
};

// API rate limiting untuk endpoint publik
const apiRateMap = new Map();
const checkApiRateLimit = (ip, limit = 60, windowMs = 60000) => {
  const now = Date.now();
  const rec = apiRateMap.get(ip);
  if (!rec || now > rec.resetAt) {
    apiRateMap.set(ip, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (rec.count >= limit) return false;
  rec.count++;
  return true;
};

// Lock set untuk mencegah race condition pada alokasi key
const processingOrders = new Set();

const checkQrRateLimit = (ip) => {
  const now = Date.now();
  const record = qrRateLimit.get(ip);
  if (record) {
    const windowStart = now - QR_RATE_WINDOW;
    const recentRequests = record.filter(ts => ts > windowStart);
    if (recentRequests.length >= QR_RATE_LIMIT) {
      return false;
    }
    recentRequests.push(now);
    qrRateLimit.set(ip, recentRequests);
  } else {
    qrRateLimit.set(ip, [now]);
  }
  return true;
};

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout');
app.set('trust proxy', 1);
app.use(expressLayouts);
app.use(express.json({
  // Signature GensPay = SHA256(rawBody + apiKey) → butuh body mentah persis seperti yang dikirim.
  verify: (req, _res, buf) => { if ((req.originalUrl || '').startsWith('/webhook/genspay')) req.rawBody = buf.toString('utf8'); }
}));
app.use(express.urlencoded({ extended: true }));
// Aset statis di-cache di browser (1 hari) DAN di CDN Vercel (s-maxage), supaya
// gambar/ikon/banner tidak memicu invocation function di setiap kunjungan.
const staticOpts = {
  setHeaders: (res, filePath) => {
    if (/sw\.js$|manifest\.webmanifest$/.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=259200, s-maxage=604800, stale-while-revalidate=86400');
    }
  }
};
app.use(express.static(path.join(__dirname, 'public'), staticOpts));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads'), staticOpts));

// ── SECURITY: header keamanan + default TANPA cache untuk semua respons dinamis ──
// (halaman berisi key / sesi tidak boleh nyangkut di CDN atau cache browser bersama).
// Route publik yang memang boleh di-cache memanggil cachePublic() dan menimpa header ini.
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Strict-Transport-Security': 'max-age=31536000',
    // Halaman berisi key/sesi: no-store. Sisanya `private, no-cache` — tetap tak boleh disimpan CDN bersama, tapi
    // browser masih boleh memakai cache back/forward (no-store membuat tombol Back selalu fetch ulang = lambat).
    'Cache-Control': /^\/(invoice|cek-pesanan|dashboard|check-payment|admin|lx-secure-panel-7k|activate-key|profile|login|register)/.test(req.path)
      ? 'private, no-store' : 'private, no-cache'
  });
  next();
});

// Redirect hanya ke path internal (cegah open-redirect: //evil.com, /\evil.com, https://evil.com)
function safeRedirect(v, fallback = '/') {
  const s = typeof v === 'string' ? v : '';
  return /^\/(?![\/\\])[^\r\n]*$/.test(s) ? s : fallback;
}
// Ekstensi upload di-whitelist (nama file asli dari klien tidak dipercaya)
function safeExt(name) {
  const e = path.extname(String(name || '')).toLowerCase();
  return ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(e) ? e : '.jpg';
}
// Rahasia yang tersimpan di DB tidak pernah dikirim utuh ke browser admin
const maskSecret = (v) => { const s = String(v || ''); return s ? '••••' + (s.length > 12 ? s.slice(-4) : '') : ''; };
const isMaskedSecret = (v) => typeof v === 'string' && v.startsWith('••••');
function maskSettingsForAdmin(settings) {
  const s = { ...(settings || {}) };
  delete s.adminPassword;
  if (s.fonnteToken) s.fonnteToken = maskSecret(s.fonnteToken);
  if (s.pakasir) s.pakasir = { ...s.pakasir, apiKey: maskSecret(s.pakasir.apiKey) };
  return s;
}
// Rate limiter sederhana per-key (per-instance; lapisan tambahan, bukan satu-satunya pertahanan)
const makeLimiter = (limit, windowMs) => {
  const m = new Map();
  return (key) => {
    const now = Date.now();
    const r = m.get(key);
    if (!r || now > r.resetAt) {
      if (m.size > 5000) for (const [k, v] of m) if (now > v.resetAt) m.delete(k);
      m.set(key, { count: 1, resetAt: now + windowMs });
      return true;
    }
    if (r.count >= limit) return false;
    r.count++;
    return true;
  };
};
const registerLimiter = makeLimiter(5, 60 * 60 * 1000); // 5 pendaftaran / jam / IP
const orderLimiter = makeLimiter(10, 10 * 60 * 1000);   // 10 create-order / 10 menit / user

// Cari 1 transaksi lewat kode order tanpa menarik seluruh transactions.json (RPC; fallback ke cara lama)
const findTxByCode = async (code) => {
  const c = String(code || '').trim().toUpperCase();
  if (!c || c.length > 24) return null;
  const lite = await db.readTxBy('code', c);
  if (lite !== undefined) return lite;
  return (await db.readFresh('transactions.json')).find(t => t.code === c) || null;
};
// QR string hanya berguna selama pesanan pending — buang dari transaksi lama supaya transactions.json tidak membengkak
const compactTransactions = (list) => {
  const now = Date.now();
  for (const t of list) {
    if (t.qrString && (t.status !== 'pending' || now - new Date(t.createdAt).getTime() > 24 * 3600 * 1000)) delete t.qrString;
  }
};

// Helper: izinkan CDN Vercel meng-cache respons API PUBLIK (tanpa data per-user).
const cachePublic = (res, sMaxAge = 30, swr = 120) =>
  res.set('Cache-Control', `public, max-age=15, s-maxage=${sMaxAge}, stale-while-revalidate=${swr}`);

app.use(cookieSession({
  name: 'lx_session',
  secret: process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex'),
  maxAge: 7 * 24 * 60 * 60 * 1000,
  httpOnly: true,
  sameSite: 'lax',
  // JANGAN paksa secure:true — kalau NODE_ENV=production tapi dibuka lewat
  // http://localhost, cookie-session melempar error / cookie tidak pernah
  // tersimpan, jadi login "berhasil" lalu langsung mental lagi. Biarkan
  // auto-detect berdasarkan koneksi (trust proxy sudah aktif untuk Vercel).
}));

// ── FIX: Regenerate session object tiap request (cookie-session quirk) ──
app.use((req, res, next) => {
  // Pastikan session object tidak null
  if (!req.session) req.session = {};
  next();
});

// Inject settings + isAdmin ke semua view otomatis
app.use(async (req, res, next) => {
  // Kalau cache settings kosong, fetch dari Supabase dulu
  let settings = readDB('settings.json');
  if (!settings || Object.keys(settings).length === 0) {
    settings = await db.readFresh('settings.json').catch(() => ({}));
  }
  // Logo toko = wordmark teks bawaan. URL logo lama (gambar bulat / brand lama) otomatis diganti.
  const view = { ...(settings || {}) };
  if (!view.logoUrl || /logo-(luxzco|angga|vipr)[^/]*\.png/i.test(view.logoUrl) && !/logo-luxzco-text/.test(view.logoUrl)) view.logoUrl = '/uploads/logo-luxzco-text.png';
  if (!view.faviconUrl || /favicon-(luxzco|angga|vipr)[^/]*\.png/i.test(view.faviconUrl)) view.faviconUrl = '/uploads/favicon-lx.png';
  view.contact = { ...(view.contact || {}) };
  if (!view.contact.waChannel && /^0029/.test(view.contact.telegram || '')) { view.contact.waChannel = view.contact.telegram; view.contact.telegram = ''; }
  // SECURITY: view publik tidak boleh pernah menerima hash password admin,
  // API key PakKasir, atau token Fonnte. Route admin mengirim `settings`
  // lengkap sendiri (readFresh) lewat res.render, jadi tidak terpengaruh.
  delete view.adminPassword;
  delete view.fonnteToken;
  delete view.pakasir;
  res.locals.settings = view;
  res.locals.buildVersion = APP_VERSION;
  res.locals.integrations = { genspay: genspay.isConfigured(), ghostseller: ghostseller.isConfigured(), dripstore: dripstore.isConfigured(), appUrl: !!process.env.APP_URL };
  res.locals.isAdmin = !!(req.session?.isAdmin || req.session?.userId === 'admin');
  res.locals.user = getSessionUser(req);
  next();
});

// Setup upload — gunakan /tmp di Vercel (satu-satunya writable path)
const isVercel = process.env.VERCEL === '1' || process.env.NOW_REGION;
const uploadsBase = isVercel ? '/tmp' : path.join(__dirname, 'public', 'uploads');
const uploadsDir = isVercel ? '/tmp/products' : path.join(__dirname, 'public', 'uploads', 'products');

// Buat direktori lokal hanya jika bukan Vercel
if (!isVercel) {
  if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = isVercel ? '/tmp/products' : path.join(__dirname, 'public', 'uploads', 'products');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${uuidv4()}${safeExt(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Hanya file gambar yang diizinkan'), false);
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: fileFilter
});

// Database helpers (Supabase)
const dbPath = path.join(__dirname, 'database');
if (!isVercel && !fs.existsSync(dbPath)) fs.mkdirSync(dbPath, { recursive: true });

const readDB = db.readDB;
const writeDB = db.writeDB;
const readFresh = db.readFresh;
const readSmart = db.readSmart; // TTL-based: auto-refresh jika cache >8 detik
const refreshForWrite = (...files) => Promise.all(files.map(f => db.refreshFromDB(f)));

// Initialize database files with defaults (only if truly missing)
const initDB = async () => {
  // JANGAN hardcode username/password admin di source code (ini yang
  // sebelumnya bocor lewat GitHub). Kalau env var tidak diset, generate
  // password random tiap kali server start dari nol, dan print SEKALI ke
  // log server (bukan ke kode) supaya bisa langsung dipakai lalu diganti.
  const crypto = require('crypto');
  // .trim(): copy-paste ke Vercel env sering membawa spasi/newline tak kasat mata
  // di ujung value — itu bikin username/password "terlihat benar tapi selalu salah".
  const fallbackUsername = (process.env.INITIAL_ADMIN_USERNAME || '').trim() || 'admin';
  const envAdminPassword = (process.env.INITIAL_ADMIN_PASSWORD || '').trim();
  const fallbackPassword = envAdminPassword || crypto.randomBytes(9).toString('base64url');
  if (!envAdminPassword) {
    console.log('🔐 Belum ada INITIAL_ADMIN_PASSWORD di env. Password admin awal di-generate random:');
    console.log(`   username: ${fallbackUsername}`);
    console.log(`   password: ${fallbackPassword}`);
    console.log('   GANTI password ini lewat Admin Panel setelah login pertama!');
  }
  const defaultSettings = {
    siteName: 'Luxzco',
    gamePanelName: 'Luxzco',
    about: 'Luxzco menjual key lisensi dan produk digital untuk game favoritmu, dengan pembayaran QRIS dan konfirmasi langsung dari admin.',
    marqueeText: 'Bayar mudah via QRIS|Pesanan dikonfirmasi langsung oleh admin|Key tampil di halaman Cek Pesanan|Stok diperbarui langsung oleh admin',
    contact: {
      whatsapp: '',
      telegram: '',
      tiktok: '',
      apkChannel: '',
      email: ''
    },
    fonnteToken: '',
    pakasir: { apiKey: '', project: '', mode: 'production' },
    adminUsername: fallbackUsername,
    adminPassword: bcrypt.hashSync(fallbackPassword, 12),
    adminLockEnabled: true,
    logoUrl: '/uploads/logo-luxzco-text.png',
    faviconUrl: '/uploads/favicon-lx.png',
    theme: {
      primaryColor: '#06b6d4',
      secondaryColor: '#22d3ee',
      accentColor: '#67e8f9',
      backgroundColor: '#09090b',
      cardBackground: '#111113',
      borderColor: 'rgba(79,123,255,.18)',
      glowColor: 'rgba(79,123,255,0.55)'
    },
    categories: ['freefire', 'mlbb', 'pubgm', 'sertifikat'],
    categoryLabels: { freefire: 'FREE FIRE', mlbb: 'MOBILE LEGENDS', pubgm: 'PUBG MOBILE', sertifikat: 'SERTIFIKAT' },
    resellerEnabled: true,
    resellerPrice: 50000,
    resellerDiscount: 20,
    resellerNote: 'Dapatkan diskon eksklusif untuk semua produk!',
    popularProductIds: [],
    banners: [
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
    ]
  };

  const arrayFiles = ['users.json', 'products.json', 'transactions.json', 'testimonials.json', 'notifications.json', 'keyspool.json', 'vouchers.json'];

  // Seed arrays only if they don't exist at all
  for (const filename of arrayFiles) {
    const current = readDB(filename);
    if (!Array.isArray(current)) {
      await writeDB(filename, []);
    }
  }

  // Settings: merge defaults + existing. Jangan overwrite data yang sudah ada.
  const currentSettings = readDB('settings.json');
  if (!currentSettings || Object.keys(currentSettings).length === 0) {
    // Supabase kosong — push default penuh
    await writeDB('settings.json', defaultSettings);
    console.log('✅ Settings seeded with defaults');
  } else {
    // Merge: tambah field yang belum ada, jangan overwrite yang sudah ada
    let dirty = false;
    for (const [k, v] of Object.entries(defaultSettings)) {
      if (currentSettings[k] === undefined || currentSettings[k] === null) {
        currentSettings[k] = v;
        dirty = true;
      }
    }

    // Reset paksa kredensial admin — hanya jalan kalau FORCE_RESET_ADMIN=true
    // di env. Set env ini + INITIAL_ADMIN_USERNAME/PASSWORD, lalu redeploy.
    // SETELAH berhasil login, HAPUS lagi env FORCE_RESET_ADMIN supaya tidak
    // ke-reset terus tiap kali server restart/redeploy.
    if (process.env.FORCE_RESET_ADMIN === 'true') {
      currentSettings.adminUsername = fallbackUsername;
      currentSettings.adminPassword = bcrypt.hashSync(fallbackPassword, 12);
      dirty = true;
      console.log('🔐 FORCE_RESET_ADMIN aktif — kredensial admin di-reset ke:');
      console.log(`   username: ${fallbackUsername}`);
      console.log(`   password: ${fallbackPassword}`);
      console.log('⚠️  Jangan lupa HAPUS env FORCE_RESET_ADMIN setelah berhasil login!');
    }

    if (dirty) {
      await writeDB('settings.json', currentSettings);
      console.log('✅ Settings merged missing fields');
    }
  }
};

// Vercel: export app langsung (Vercel tidak pakai app.listen)
// Lokal: jalankan server setelah DB siap
if (isVercel) {
  // ── VERCEL FIX: pastikan DB init selesai sebelum request diproses ──
  let dbReady = false;
  let dbInitPromise = null;

  const ensureDBReady = async () => {
    if (dbReady) return;
    if (!dbInitPromise) {
      dbInitPromise = db.initializeDB().then(() => initDB()).then(() => { dbReady = true; });
    }
    await dbInitPromise;
  };

  // Middleware: block request sampai DB siap (max 8 detik)
  app.use(async (req, res, next) => {
    try {
      await Promise.race([
        ensureDBReady(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('DB init timeout')), 8000))
      ]);
    } catch (e) {
      console.error('[DB] Init failed or timeout:', e.message);
      // Lanjut saja, pakai local fallback
    }
    next();
  });

  module.exports = app;
} else {
  // Lokal / VPS: tunggu DB siap baru listen
  db.initializeDB().then(() => {
    initDB(); // seed defaults only if missing
    app.listen(PORT, () => {
      console.log(`✅ Server berjalan di http://localhost:${PORT}`);
      console.log(`📁 Database: ${dbPath}`);
      console.log(`🔐 Admin: /admin`);
    });
  }).catch(err => {
    console.error('Fatal: Failed to initialize database:', err);
    process.exit(1);
  });
  module.exports = app;
}

// Helper: dapatkan user dari session (support admin yang tidak ada di users.json)
const getSessionUser = (req) => {
  if (req.session?.isAdmin) {
    const s = readDB('settings.json');
    return { id: 'admin', username: s.adminUsername || 'Admin', isAdmin: true, photo: null, role: 'admin', is_reseller: false };
  }
  if (req.session?.userId) {
    const u = readDB('users.json').find(u => u.id === req.session.userId);
    if (!u) return null;
    const { password: _pw, ...safe } = u; // SECURITY: hash password tidak boleh ikut ke view / res.locals
    return safe;
  }
  return null;
};

// Auth middleware
const requireAuth = (req, res, next) => {
  if (!req.session?.userId) {
    if (req.xhr || req.headers['content-type']?.includes('application/json')) {
      return res.json({ success: false, message: 'Silakan login terlebih dahulu', redirect: '/login' });
    }
    return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }
  next();
};

const requireAdmin = async (req, res, next) => {
  if (!req.session?.isAdmin && req.session?.userId !== 'admin') {
    // Balas 404 bukan 403 agar penyerang tidak tahu route admin ada
    return res.status(404).send('Not found');
  }

  try {
    // ── Single-Device Admin Lock ──────────────────────────────────
    // Mencegah 2 orang (mis: web dev + client) login admin bersamaan di
    // device berbeda. Login bersamaan menyebabkan race condition saat
    // keduanya baca-ubah-simpan data produk di waktu hampir sama, sehingga
    // perubahan salah satu pihak tertimpa / produk "berubah-ubah" saat refresh.
    //
    // PENTING: pakai readFresh (bukan readDB) di sini. Vercel menjalankan
    // banyak instance serverless yang TIDAK berbagi memori — kalau pakai
    // cache lokal, satu instance bisa "telat tahu" kalau device lain baru
    // saja ambil alih sesi, dan tetap meloloskan device yang seharusnya
    // sudah diblokir. Ini satu-satunya pengecekan yang wajib selalu fresh.
    const lockSettings = await db.readSmart('settings.json'); // flag adminLockEnabled boleh agak basi; admin-lock.json di bawah tetap fresh
    const lockEnabled = lockSettings?.adminLockEnabled !== false; // default: aktif
    let lock; // deklarasi di luar blok — dipakai lagi di touchAdminLock() di bawah
    if (lockEnabled) {
      lock = await db.readFresh('admin-lock.json');
      if (isLockActive(lock) && lock.sessionId !== req.session.adminSessionId) {
        req.session = null; // paksa logout sesi yang sudah digantikan
        if (ADMIN_PAGE_ROUTES.has(req.path)) {
          return res.redirect('/lx-secure-panel-7k?kicked=1');
        }
        return res.status(401).json({
          success: false,
          sessionRevoked: true,
          message: `Sesi admin Anda diakhiri karena ada login dari perangkat lain (${lock.device || 'perangkat lain'}).`
        });
      }
    }

    // Sesi ini pemegang lock yang sah → perpanjang heartbeat (di-throttle,
    // supaya tidak nulis ke Supabase di setiap request)
    touchAdminLock(req.session.adminSessionId, lock);

    next();
  } catch (err) {
    // SAFETY NET: kalau ada bug tak terduga di blok di atas, jangan biarkan
    // request menggantung sampai Vercel timeout (504) — langsung balas error
    // dan tetap izinkan request lanjut (fail-open) supaya panel admin tidak
    // ikut lumpuh total gara-gara 1 fitur lock ini.
    console.error('requireAdmin error (fail-open, lock check dilewati):', err);
    next();
  }
};

// Halaman admin yang dimuat lewat navigasi browser biasa (bukan fetch/XHR)
// → kalau lock-nya hilang, redirect ke halaman login, bukan balas JSON.
const ADMIN_PAGE_ROUTES = new Set(['/admin', '/admin/product-edit', '/admin/theme-settings']);

// Lock dianggap kosong/expired kalau tidak ada heartbeat selama ini
// (mis: tab ditutup / koneksi putus tanpa logout resmi).
const ADMIN_LOCK_TIMEOUT_MS = 6 * 60 * 1000; // 6 menit

const parseDeviceLabel = (ua = '') => {
  let browser = 'Browser';
  if (/edg/i.test(ua)) browser = 'Edge';
  else if (/chrome/i.test(ua)) browser = 'Chrome';
  else if (/firefox/i.test(ua)) browser = 'Firefox';
  else if (/safari/i.test(ua)) browser = 'Safari';
  let os = 'Unknown';
  if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad|ios/i.test(ua)) os = 'iOS';
  else if (/windows/i.test(ua)) os = 'Windows';
  else if (/mac os/i.test(ua)) os = 'Mac';
  else if (/linux/i.test(ua)) os = 'Linux';
  return `${browser} · ${os}`;
};

const isLockActive = (lock) => {
  if (!lock || !lock.sessionId || !lock.lastSeen) return false;
  return (Date.now() - new Date(lock.lastSeen).getTime()) < ADMIN_LOCK_TIMEOUT_MS;
};

// Klaim lock untuk sesi admin yang baru login. Dipanggil SETELAH password
// terverifikasi & lock lama dipastikan kosong/expired (lihat route login).
const acquireAdminLock = async (req) => {
  const sessionId = uuidv4();
  await writeDB('admin-lock.json', {
    sessionId,
    ip: req.ip,
    device: parseDeviceLabel(req.headers['user-agent'] || ''),
    loginAt: new Date().toISOString(),
    lastSeen: new Date().toISOString()
  });
  return sessionId;
};

// Lepas lock saat logout resmi — supaya device lain bisa langsung login
// tanpa harus menunggu timeout.
const releaseAdminLock = async (sessionId) => {
  if (!sessionId) return;
  try {
    const lock = await db.readFresh('admin-lock.json');
    if (lock && lock.sessionId === sessionId) await writeDB('admin-lock.json', {});
  } catch {}
};

// Heartbeat di-throttle per sessionId supaya tidak nulis ke Supabase di
// setiap request admin (cukup tiap ≥60 detik aktivitas). `lock` di sini
// sudah hasil readFresh dari requireAdmin, jadi tidak perlu baca ulang.
const lastHeartbeatAt = new Map();
const touchAdminLock = (sessionId, lock) => {
  if (!sessionId || !lock || lock.sessionId !== sessionId) return;
  const now = Date.now();
  if (now - (lastHeartbeatAt.get(sessionId) || 0) < 60000) return;
  lastHeartbeatAt.set(sessionId, now);
  writeDB('admin-lock.json', { ...lock, lastSeen: new Date().toISOString() }).catch(() => {});
};

// ── Alokasi key (SATU sumber kebenaran, dipakai check-payment, konfirmasi admin & webhook) ──
// Format stok: "KEY" (generik) atau "KEY:TAG" dengan TAG durasi: "3" / "3d" = 3 hari, "3h" = 3 jam.
// Mengambil key langsung memotongnya dari array (splice) dan HANYA mengembalikan bagian KEY
// (tanpa ":TAG"), jadi label internal tidak pernah ikut terkirim ke pembeli.
// Key yang di-tag durasi LAIN tidak pernah dipakai (cegah 1 jam kebagian jatah 30 hari).
const takeKeyFromProduct = (product, token) => {
  if (!product || !Array.isArray(product.keys) || product.keys.length === 0) return null;
  const t = token == null ? null : String(token);
  if (t) {
    const idx = product.keys.findIndex(k => dur.splitKeyTag(k).token === t);
    if (idx !== -1) return dur.splitKeyTag(product.keys.splice(idx, 1)[0]).key;
  }
  const gi = product.keys.findIndex(k => dur.splitKeyTag(k).token === null);
  if (gi !== -1) return String(product.keys.splice(gi, 1)[0]);
  return null;
};

// Stok lokal yang BENAR-BENAR bisa dijual untuk durasi ini = key ber-tag durasi itu + key generik
// (persis urutan yang dipakai takeKeyFromProduct).
const countKeysForToken = (keys, token) => {
  const all = keys || [];
  const generic = all.filter(k => dur.splitKeyTag(k).token === null).length;
  if (!token) return generic;
  return generic + all.filter(k => dur.splitKeyTag(k).token === String(token)).length;
};

// ── Auto-restock (provider: Ghostseller | Drip Store — dipilih per produk) ──
// product.gsMap = { provider, productId, durations: { '<token>': '<durationId/variantId>' }, cooldown: { '<token>': ISO } }
// (data lama tanpa `provider` = Ghostseller)
const PROVIDERS = { ghostseller, dripstore };
const GS_COOLDOWN_MS = 10 * 60 * 1000;
const gsMappingFor = (product, token) => {
  const m = product && product.gsMap;
  const durationId = m && m.durations && token ? m.durations[token] : null;
  if (!(m && m.productId && durationId)) return null;
  const provider = PROVIDERS[m.provider] ? m.provider : 'ghostseller';
  return { provider, productId: m.productId, durationId };
};
const gsOnCooldown = (product, token) => {
  const t = product && product.gsMap && product.gsMap.cooldown && product.gsMap.cooldown[token];
  return !!t && new Date(t).getTime() > Date.now();
};
// Durasi ini bisa dijual lewat provider (terkonfigurasi + terpetakan + tidak sedang "libur" karena error permanen)?
const gsSellable = (product, token) => {
  const map = gsMappingFor(product, token);
  return !!map && PROVIDERS[map.provider].isConfigured() && !gsOnCooldown(product, token);
};

// Tersedia SEKARANG? = bisa dijual lewat provider DAN (bila cache stok provider sudah ada) stok/saldo tidak habis.
// null dari peek = belum diketahui → dianggap tersedia; yang memastikan adalah preflight saat checkout.
const gsAvailable = (product, token) => {
  if (!gsSellable(product, token)) return false;
  const map = gsMappingFor(product, token);
  const prov = PROVIDERS[map.provider];
  return !(prov.peekAvailability && prov.peekAvailability(map.productId, map.durationId) === false);
};
// Segarkan cache katalog provider yang dipakai produk-produk ini (maks. 1x/menit per instance; dibatasi 2 dtk agar halaman tak lambat).
const warmProviders = async (products) => {
  const names = new Set();
  for (const p of products || []) {
    const m = p.gsMap;
    const n = m && m.productId ? (PROVIDERS[m.provider] ? m.provider : 'ghostseller') : null;
    if (n && PROVIDERS[n].peekAvailability && PROVIDERS[n].isConfigured()) names.add(n);
  }
  await Promise.all([...names].map(n => Promise.race([
    PROVIDERS[n].fetchCatalog().then(() => (PROVIDERS[n].getBalance ? PROVIDERS[n].getBalance().catch(() => null) : null)).catch(() => null),
    new Promise(r => setTimeout(r, 2000)),
  ])));
};

const GS_REASON_TEXT = {
  insufficient_balance: 'Saldo akun provider tidak cukup — top up saldo lalu proses manual.',
  out_of_stock: 'Stok di provider habis untuk paket ini.',
  unauthorized: 'API key/token provider ditolak — cek environment (GHOSTSELLER_API_KEY / DRIPSTORE_API_TOKEN).',
  invalid_product_or_duration: 'Mapping produk/durasi provider tidak valid — perbarui di Admin → Produk.',
  not_configured: 'API key provider belum diisi di environment.',
  gs_not_configured: 'API key provider belum diisi di environment.',
  no_stock: 'Stok lokal kosong dan durasi ini belum dipetakan ke provider auto-restock.',
  cloudflare_challenge: 'Cloudflare menahan request ke provider — IP server (Vercel) belum di-allowlist oleh penyedia. Hubungi penyedia.',
  ip_blocked: 'IP server ditolak provider (allowlist IP). Hubungi penyedia.',
  forbidden: 'Akses ditolak provider (403).',
  key_cap: 'Batas per-key di provider tercapai (423).',
  ambiguous: 'Koneksi ke provider terputus SAAT membuat key — saldo mungkin sudah terpotong. JANGAN kirim ulang otomatis: cek Riwayat/History di dashboard provider dulu; kalau key sudah terbit, kirim ke pembeli, kalau belum baru proses ulang.',
  ambiguous_prior_attempt: 'Percobaan sebelumnya ke provider tidak jelas hasilnya (mungkin sudah memotong saldo). Cek Riwayat/History di dashboard provider dulu sebelum mengirim ulang.',
  unparseable_success: 'Provider mengembalikan sukses tapi format key tidak dikenali (saldo kemungkinan terpotong) — lihat detail di bawah, kirim key manual.',
  rate_limited: 'Provider membatasi request (429), sudah dicoba beberapa kali.',
  provider_error: 'Provider gagal merespons / menolak permintaan.',
  timeout: 'Provider timeout.',
  network: 'Tidak bisa terhubung ke provider.',
};

// Alokasi 1 key untuk transaksi lunas: stok lokal dulu -> provider auto-restock (jika durasi ini dipetakan).
//  • Provider idempoten (Ghostseller): idempotencyKey = kode order → retry aman, tak pernah terbit 2 key.
//  • Provider TANPA idempotency (Drip Store): sebelum memanggil, "percobaan" dicatat ke DB (tx.providerAttemptAt).
//    Kalau hasilnya tidak jelas (timeout/jaringan putus/5xx → saldo mungkin terpotong) percobaan TIDAK PERNAH
//    diulang otomatis — ditandai manual. Hanya kegagalan yang PASTI belum diproses (429, 401/403, saldo/stok
//    habis, dst.) yang menghapus catatan itu sehingga boleh dicoba lagi.
const allocateKeyFor = async (tx, product, persistTx) => {
  const token = dur.txToken(tx);
  const local = takeKeyFromProduct(product, token);
  if (local) return { key: local, source: 'local' };
  const map = gsMappingFor(product, token);
  if (!map) return { key: null, reason: 'no_stock', transient: false };
  const prov = PROVIDERS[map.provider];
  if (!prov.isConfigured()) return { key: null, reason: 'gs_not_configured', transient: false };

  if (!prov.idempotent) {
    if (tx.providerAttemptAt) return { key: null, reason: 'ambiguous_prior_attempt', transient: false, ambiguous: true, token };
    tx.providerAttemptAt = new Date().toISOString();
    if (persistTx) await persistTx(); // tercatat SEBELUM panggilan: kalau fungsi mati di tengah jalan, tidak akan memanggil dua kali
  }
  try {
    const r = await prov.generateKey({ productId: map.productId, durationId: map.durationId, idempotencyKey: tx.code });
    delete tx.providerAttemptAt;
    return { key: r.keyString, source: map.provider, cost: r.price, currency: r.currency, token };
  } catch (e) {
    const ambiguous = !prov.idempotent && !!e.maybeCharged;
    if (!prov.idempotent && !ambiguous) delete tx.providerAttemptAt; // pasti belum diproses → boleh dicoba lagi
    return { key: null, reason: ambiguous ? 'ambiguous' : (e.code || 'provider_error'), message: e.message, transient: !!e.transient && !ambiguous, ambiguous, token, detail: e.code === 'unparseable_success' ? e.message : undefined };
  }
};

const MAX_FULFILL_ATTEMPTS = 6;
const FULFILL_RETRY_GAP_MS = 15000;

// Catat notifikasi pembelian (toast "baru saja membeli") — hanya untuk pesanan yang key-nya benar-benar terkirim.
const pushPurchaseNotif = async (tx) => {
  try {
    const notifs = await readFresh('notifications.json');
    notifs.unshift({ id: uuidv4(), type: 'purchase', buyerName: tx.customerName,
      buyerPhoto: null, productName: tx.productName,
      price: tx.price, time: tx.paidAt, timeStr: formatDate(new Date(tx.paidAt)) });
    await writeDB('notifications.json', notifs.slice(0, 50));
  } catch (e) { console.error('[notif] gagal:', e.message); }
};

/**
 * Selesaikan transaksi produk yang SUDAH LUNAS: alokasi key (stok lokal → Ghostseller), simpan, notifikasi.
 * Pemanggil WAJIB memegang lock processingOrders untuk tx.id dan memberi `transactions`
 * (hasil readFresh) yang memuat objek `tx` itu.
 * @returns {Promise<{status:'done', key:string|null, outOfStock:boolean} | {status:'delivering'}>}
 */
const deliverPaidOrder = async (tx, transactions, { settings, confirmedBy } = {}) => {
  const products = await readFresh('products.json');
  const product = products.find(p => p.id === tx.productId);
  const alloc = await allocateKeyFor(tx, product, () => writeDB('transactions.json', transactions));
  const now = new Date().toISOString();
  tx.paymentConfirmed = true;
  tx.paidAt = tx.paidAt || now;
  if (confirmedBy) tx.confirmedBy = confirmedBy;

  if (alloc.key) {
    if (product) { product.sold = (product.sold || 0) + 1; await writeDB('products.json', products); }
    tx.status = 'done'; tx.key = alloc.key; tx.outOfStock = false; tx.keySource = alloc.source; delete tx.qrString;
    if (alloc.cost) { tx.providerCost = alloc.cost; if (alloc.currency) tx.providerCurrency = alloc.currency; }
    delete tx.lastFulfillError;
    await writeDB('transactions.json', transactions);
    await pushPurchaseNotif(tx);
    return { status: 'done', key: alloc.key, outOfStock: false };
  }

  // Gagal dapat key. Error sementara (429/502/timeout/jaringan): jangan tandai habis dulu, coba lagi nanti.
  tx.lastFulfillAt = now;
  tx.lastFulfillError = alloc.reason === 'unparseable_success' ? 'unparseable_success' : alloc.reason;
  if (alloc.reason === 'unparseable_success' || alloc.ambiguous) { tx.keyNeedsManual = true; }
  if (alloc.transient && (tx.fulfillAttempts || 0) < MAX_FULFILL_ATTEMPTS) {
    tx.fulfillAttempts = (tx.fulfillAttempts || 0) + 1;
    await writeDB('transactions.json', transactions);
    return { status: 'delivering' };
  }

  // Permanen / percobaan habis: "libur"-kan durasi ini dari penjualan sementara (cegah orang lain bayar untuk stok yang tak ada)
  if (product && product.gsMap && alloc.token && ['insufficient_balance', 'out_of_stock', 'unauthorized', 'invalid_product_or_duration', 'cloudflare_challenge', 'ip_blocked', 'forbidden', 'key_cap'].includes(alloc.reason)) {
    product.gsMap.cooldown = { ...(product.gsMap.cooldown || {}), [alloc.token]: new Date(Date.now() + GS_COOLDOWN_MS).toISOString() };
    await writeDB('products.json', products);
  }
  tx.status = 'done'; tx.key = null; tx.outOfStock = true;
  await writeDB('transactions.json', transactions);

  const why = (GS_REASON_TEXT[alloc.reason] || alloc.message || alloc.reason || 'stok kosong') + (alloc.detail ? '\nDetail: ' + alloc.detail : '');
  const waMsg = `⚠️ PESANAN BUTUH DIPROSES MANUAL!\n\n` +
    `Order: ${tx.code}\nProduk: ${tx.productName}${tx.duration ? ' (' + tx.duration + ')' : ''}\n` +
    `Customer: ${tx.customerName} (${tx.wa || '-'})\nTotal: Rp ${Number(tx.price).toLocaleString('id-ID')}\n\n` +
    `Pembayaran sudah masuk tapi key belum terkirim.\nPenyebab: ${why}\n` +
    `Setelah beres, kirim key manual ke pembeli.`;
  if (settings) sendWhatsAppNotif(settings.contact?.whatsapp, waMsg, settings).catch(() => {});
  return { status: 'done', key: null, outOfStock: true };
};

// Helper functions
const generateOrderCode = () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  // crypto.randomInt (bukan Math.random) — kode order = "kunci" untuk melihat key
  // di halaman Cek Pesanan, jadi tidak boleh bisa diprediksi.
  let code = 'LX-';
  for (let i = 0; i < 4; i++) code += chars[crypto.randomInt(chars.length)];
  code += '-';
  for (let i = 0; i < 4; i++) code += chars[crypto.randomInt(chars.length)];
  return code;
};

// ── Timezone bisnis: WIB (Asia/Jakarta, UTC+7) ──
// BUG LAMA: formatDate() pakai d.getDate()/getHours() dkk, yang selalu
// ikut timezone SERVER (di Vercel = UTC), bukan timezone toko (WIB).
// Makanya jam yang tampil di admin panel / notif pembelian meleset ~7 jam
// dari jam Indonesia asli. Fix: selalu convert eksplisit ke Asia/Jakarta
// pakai Intl.DateTimeFormat, apapun timezone server-nya.
const APP_TIMEZONE = 'Asia/Jakarta';

const jakartaParts = (date = new Date()) => {
  const d = new Date(date);
  const parts = {};
  new Intl.DateTimeFormat('en-GB', {
    timeZone: APP_TIMEZONE,
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  }).formatToParts(d).forEach(p => { parts[p.type] = p.value; });
  return parts;
};

const formatDate = (date = new Date()) => {
  const p = jakartaParts(date);
  return `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}`;
};

// Kunci kalender harian (YYYY-MM-DD) berbasis WIB — dipakai untuk
// pengelompokan per-hari (chart revenue dkk) supaya transaksi yang
// terjadi jam 00:00-06:59 WIB tidak "nyasar" dihitung ke hari
// sebelumnya (karena jam segitu di UTC masih tanggal kemarin).
const jakartaDateKey = (date = new Date()) => {
  const p = jakartaParts(date);
  return `${p.year}-${p.month}-${p.day}`;
};

// Label tanggal pendek buat chart, contoh: "Sen, 6 Jul" — eksplisit WIB.
const jakartaDayLabel = (date = new Date()) => new Intl.DateTimeFormat('id-ID', {
  timeZone: APP_TIMEZONE, weekday: 'short', day: 'numeric', month: 'short'
}).format(new Date(date));

// Hitung ULANG field waktu tampilan dari createdAt asli setiap kali
// di-render, alih-alih percaya field `time` yang sudah tersimpan di DB.
// Ini penting: transaksi LAMA yang kena bug timezone di atas otomatis
// ikut ke-fix begitu halaman di-refresh, tanpa perlu migrasi data manual
// ke Supabase.
const withDisplayTime = (t) => {
  if (!t) return t;
  const refTime = (t.status === 'done' && t.paidAt) ? t.paidAt : t.createdAt;
  const ts = refTime ? new Date(refTime) : null;
  const valid = ts && !isNaN(ts.getTime());
  return { ...t, time: valid ? formatDate(ts) : (t.time || '-') };
};
const withDisplayTimeList = (list) => (list || []).map(withDisplayTime);

// ── PakKasir API (app.pakasir.com) ──
const createQRISPayment = (orderId, amount, settings) => {
  return new Promise((resolve, reject) => {
    const apiKey = settings.pakasir?.apiKey?.trim() || '';
    const project = settings.pakasir?.project?.trim() || '';
    if (!apiKey || !project) return reject(new Error('API Key atau Project PakKasir belum dikonfigurasi'));

    const body = JSON.stringify({ project, order_id: orderId, amount, api_key: apiKey });
    const req = https.request({
      hostname: 'app.pakasir.com', port: 443,
      path: '/api/transactioncreate/qris', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(data);
          const qr = r.payment?.payment_number || r.payment_number || r.qr_string || r.data?.payment_number;
          if (!qr) return reject(new Error(r.message || `Pakasir error: ${data.slice(0,100)}`));
          resolve({ qr_string: qr, total_payment: r.payment?.total_payment || amount, expired_at: r.payment?.expired_at || null });
        } catch(e) { reject(new Error('Gagal parse response PakKasir')); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('PakKasir timeout')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    req.write(body); req.end();
  });
};

// Kirim notifikasi WhatsApp otomatis ke admin via Fonnte (jika token dikonfigurasi)
const sendWhatsAppNotif = (target, message, settings) => {
  return new Promise((resolve) => {
    const token = settings?.fonnteToken?.trim() || '';
    if (!token || !target) return resolve(false);
    const body = `target=${encodeURIComponent(target)}&message=${encodeURIComponent(message)}`;
    const req = https.request({
      hostname: 'api.fonnte.com', port: 443,
      path: '/send', method: 'POST',
      headers: {
        'Authorization': token,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body)
      },
      timeout: 10000
    }, (res) => {
      res.on('data', () => {});
      res.on('end', () => resolve(true));
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.write(body); req.end();
  });
};

const checkPaymentStatus = (orderId, amount, settings) => {
  return new Promise((resolve, reject) => {
    const apiKey = settings.pakasir?.apiKey?.trim() || '';
    const project = settings.pakasir?.project?.trim() || '';
    if (!apiKey || !project) return reject(new Error('API Key PakKasir belum dikonfigurasi'));

    const q = `project=${encodeURIComponent(project)}&amount=${parseInt(amount)}&order_id=${encodeURIComponent(orderId)}&api_key=${encodeURIComponent(apiKey)}`;
    const req = https.request({
      hostname: 'app.pakasir.com', port: 443,
      path: `/api/transactiondetail?${q}`, method: 'GET', timeout: 10000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(new Error('Gagal parse response status')); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('PakKasir status timeout')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    req.end();
  });
};

// Routes - Public


// Sumber testimoni: 'real' = ulasan pembeli (butuh transaksi sukses), 'manual' = ditambahkan admin.
function testiSource(t) {
  if (t.source) return t.source;
  return (t.name && !t.userId) ? 'manual' : 'real'; // data lama: hanya input admin yang punya field "name"
}

// Buang `keys` (rahasia) dan ganti jadi angka stok. Durasi yang bisa dipenuhi Ghostseller dihitung "tersedia".
function withStockCount({ keys, ...p }) {
  const local = (keys || []).length;
  const auto = (p.items || []).some(i => {
    const d = dur.parseDuration(i.l);
    const token = d ? dur.toToken(d.n, d.unit) : null;
    return token && gsAvailable({ gsMap: p.gsMap }, token);
  });
  const { gsMap, ...rest } = p; // mapping internal tidak perlu sampai ke view publik
  return { ...rest, stockCount: auto ? Math.max(local, 999999) : local, autoRestock: auto };
}

// Rating rata-rata & jumlah ulasan per produk (dari testimonials.json) untuk kartu produk
function withProductStats(list) {
  const agg = {};
  (readDB('testimonials.json') || []).forEach(t => {
    const pid = t.productId || t.product;
    // Rating produk hanya dari ulasan pembeli asli yang ditampilkan; testimoni manual tidak ikut dihitung
    if (pid && t.verified && testiSource(t) === 'real' && t.rating >= 1 && t.rating <= 5) {
      const a = agg[pid] || (agg[pid] = { sum: 0, n: 0 });
      a.sum += t.rating; a.n++;
    }
  });
  return list.map(p => {
    const a = agg[p.id];
    return { ...p, rating: a ? Math.round((a.sum / a.n) * 10) / 10 : 0, reviewCount: a ? a.n : 0 };
  });
}

app.get('/', async (req, res) => {
  // readSmart (cache <8 dtk) — dulu readFresh: tiap pageview = 1 query Supabase yang membawa
  // SEMUA key stok. Stok akurat tetap dijamin saat create-order (readFresh di sana).
  const products = (await readSmart('products.json')).filter(p => p.status === 'active');
  await warmProviders(products);

  // ── Leaderboard real-time (hanya dari transaksi sukses) ──
  const transactions = readDB('transactions.json');
  const users = readDB('users.json');
  const userStats = {};
  transactions.forEach(t => {
    if (t.status === 'done' && t.userId) {
      if (!userStats[t.userId]) userStats[t.userId] = { userId: t.userId, totalTransactions: 0, totalSpent: 0 };
      userStats[t.userId].totalTransactions++;
      userStats[t.userId].totalSpent += t.price;
    }
  });
  const realEntries = Object.values(userStats).map(stat => {
    const u = users.find(u => u.id === stat.userId);
    return { username: u?.username || 'User', totalTransactions: stat.totalTransactions, totalSpent: stat.totalSpent };
  });
  const leaderboardEntries = realEntries
    .sort((a, b) => b.totalTransactions - a.totalTransactions || b.totalSpent - a.totalSpent)
    .slice(0, 8);

  // ── Testimoni real dari database (tidak ada lagi padding data palsu) ──
  const realTestimonials = readDB('testimonials.json')
    .filter(t => t.verified)
    .sort((a, b) => (b.featured ? 1 : 0) - (a.featured ? 1 : 0) || new Date(b.date || 0) - new Date(a.date || 0));
  const testimonialsForHome = realTestimonials.slice(0, 12).map(t => ({
    rating: t.rating, text: t.text,
    username: t.name || t.username || 'Pelanggan',
    productName: t.productName || (testiSource(t) === 'manual' ? (t.product || '') : '')
  }));
  const avgRating = testimonialsForHome.length
    ? (testimonialsForHome.reduce((s, t) => s + (t.rating || 0), 0) / testimonialsForHome.length).toFixed(1)
    : '4.9';
  const ratingCounts = {1:0,2:0,3:0,4:0,5:0};
  testimonialsForHome.forEach(t => { if (t.rating >= 1 && t.rating <= 5) ratingCounts[t.rating]++; });
  const totalSold = products.reduce((s, p) => s + (p.sold || 0), 0);
  const platformLabels = { ios: 'iOS', android: 'Android', pc: 'PC' };
  const availablePlatforms = [...new Set(products.flatMap(p => p.platforms || []))].map(p => platformLabels[p] || String(p));
  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);

  // SECURITY: strip keys sebelum dikirim ke view. stockCount = stok lokal + (999999 bila ada durasi yang
  // dijual otomatis lewat Ghostseller; Infinity jadi null di JSON → produk tampak "Habis").
  const productsSafe = withProductStats(products.map(withStockCount));

  res.render('pages/home', {
    products: productsSafe,
    settings,
    user,
    categories: settings.categories || [],
    categoryLabels: settings.categoryLabels || {},
    resellerSettings: {
      enabled: settings.resellerEnabled !== false,
      price: settings.resellerPrice || 50000,
      discount: settings.resellerDiscount || 20
    },
    leaderboardEntries,
    testimonialsForHome,
    avgRating,
    ratingCounts,
    totalSold,
    availablePlatforms
  });
});


// Halaman daftar semua produk (search + filter platform/kategori)
app.get('/products', async (req, res) => {
  const all = (await readSmart('products.json')).filter(p => p.status === 'active');
  await warmProviders(all);
  const products = withProductStats(all.map(withStockCount));
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);
  res.render('pages/products', {
    products, settings, user,
    categories: settings.categories || [],
    categoryLabels: settings.categoryLabels || {},
    pageTitle: 'Produk'
  });
});

// Cek build yang sedang jalan (tanpa login, tanpa data sensitif). 404 di sini = yang ter-deploy masih build LAMA.
app.get('/__build', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    app: 'vipluxzco', version: APP_VERSION,
    commit: (process.env.VERCEL_GIT_COMMIT_SHA || '').slice(0, 7) || null,
    modules: { genspay: true, dripstore: true, ghostseller: true, durations: true },
  });
});

// ── Webhook GensPay ──
// Header X-GensPay-Signature = hex(SHA256(rawBody + GENSPAY_API_KEY)). Tanpa signature valid → 401.
// Balasan: 2xx = diterima (GensPay berhenti mengulang) | 503 = "coba lagi" (pengiriman key tertunda, GensPay
// mengulang hingga 5x dengan backoff) | 401 hanya untuk signature palsu.
app.post('/webhook/genspay', async (req, res) => {
  const raw = req.rawBody;
  if (typeof raw !== 'string' || !genspay.verifySignature(raw, req.get('x-genspay-signature'))) {
    console.warn('[genspay-webhook] signature tidak valid dari', req.ip);
    return res.status(401).json({ error: 'invalid_signature' });
  }
  const evt = req.body || {};
  if (evt.event !== 'transaction.updated') return res.json({ ok: true, ignored: evt.event || 'unknown' });
  const d = evt.data || {};
  const orderId = typeof d.order_id === 'string' ? d.order_id : null;
  if (!orderId) return res.status(400).json({ error: 'bad_payload' });
  const status = String(d.status || '').toUpperCase();

  const orderLock = 'gp:' + orderId;
  if (processingOrders.has(orderLock)) return res.status(503).json({ error: 'busy' });
  processingOrders.add(orderLock);
  let txLock = null;
  try {
    const transactions = await readFresh('transactions.json');
    const tx = transactions.find(t => t.gateway === 'genspay' && t.orderId === orderId);
    if (!tx) return res.json({ ok: true, ignored: 'no_such_order' }); // 200: jangan diulang terus
    if (tx.status === 'done') return res.json({ ok: true, already: 'done' });

    txLock = tx.id;
    if (processingOrders.has(txLock)) return res.status(503).json({ error: 'busy' });
    processingOrders.add(txLock);

    if (status === 'EXPIRED' || status === 'FAILED') {
      if (tx.status === 'pending' && !tx.paymentConfirmed) { tx.status = 'expired'; await writeDB('transactions.json', transactions); }
      return res.json({ ok: true, status });
    }
    if (status !== 'SUCCESS') return res.json({ ok: true, ignored: status || 'unknown_status' });

    if (!genspay.isAmountEnough(d, tx.price)) {
      console.error(`[genspay-webhook] nominal kurang: order=${orderId} harga=${tx.price} amount=${d.amount} net=${d.net_amount}`);
      tx.paymentNote = `Nominal GensPay kurang dari harga (amount=${d.amount}, net=${d.net_amount})`;
      await writeDB('transactions.json', transactions);
      return res.json({ ok: true, ignored: 'amount_too_low' }); // 200: mengulang tidak akan membuatnya cukup
    }

    if (tx.type === 'reseller') {
      await upgradeToReseller(tx, transactions);
      return res.json({ ok: true, type: 'reseller' });
    }
    const settings = await readFresh('settings.json');
    const r = await deliverPaidOrder(tx, transactions, { settings, confirmedBy: 'genspay' });
    if (r.status === 'delivering') return res.status(503).json({ error: 'delivery_pending' });
    return res.json({ ok: true, delivered: !r.outOfStock });
  } catch (e) {
    console.error('[genspay-webhook] error:', e.message);
    return res.status(500).json({ error: 'internal' });
  } finally {
    processingOrders.delete(orderLock);
    if (txLock) processingOrders.delete(txLock);
  }
});

// Auth routes
app.get('/login', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.render('pages/login', {
    error: null,
    redirect: safeRedirect(req.query.redirect),
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
  });
});

app.post('/login', async (req, res) => {
  const ip = req.ip;
  const { blocked, wait } = checkLoginBlocked(ip);
  if (blocked) {
    return res.render('pages/login', {
      error: `Terlalu banyak percobaan login. Coba lagi dalam ${wait} menit.`,
      redirect: safeRedirect(req.body.redirect),
      turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    });
  }

  // ── Verifikasi Cloudflare Turnstile ─────────────────────────────────────
  if (process.env.TURNSTILE_SECRET_KEY) {
    const token = req.body['cf-turnstile-response'];
    if (!token) {
      return res.render('pages/login', {
        error: 'Verifikasi keamanan diperlukan. Mohon selesaikan captcha.',
        redirect: safeRedirect(req.body.redirect),
        turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
      });
    }
    const valid = await verifyTurnstile(token);
    if (!valid) {
      return res.render('pages/login', {
        error: 'Verifikasi keamanan gagal. Coba lagi.',
        redirect: safeRedirect(req.body.redirect),
        turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
      });
    }
  }
  // ────────────────────────────────────────────────────────────────────────

  const { username, password } = req.body;
  const settings = readDB('settings.json');

  // Admin login diblokir dari /login — gunakan halaman khusus
  if (username === settings.adminUsername) {
    recordLoginFail(ip);
    return res.render('pages/login', {
      error: 'Username atau password salah.',
      redirect: safeRedirect(req.body.redirect),
      turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    });
  }

  // Check user
  const users = readDB('users.json');
  const user = users.find(u => u.username === username);

  if (user && await bcrypt.compare(password, user.password)) {
    clearLoginFail(ip);
    req.session.userId = user.id;
    req.session.isAdmin = (user.role === 'admin');
    return res.redirect(req.body.redirect ? safeRedirect(req.body.redirect) : (req.session.isAdmin ? '/admin' : '/'));
  }

  recordLoginFail(ip);
  const remaining = LOGIN_MAX_FAIL - (loginFailMap.get(ip)?.count || 0);
  const errMsg = remaining > 0
    ? `Username atau password salah. Sisa percobaan: ${remaining}`
    : `Terlalu banyak percobaan login. Coba lagi dalam 15 menit.`;
  res.render('pages/login', {
    error: errMsg,
    redirect: safeRedirect(req.body.redirect),
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
  });
});

app.get('/register', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.render('pages/register', { error: null });
});

app.post('/register', async (req, res) => {
  const username = String(req.body.username ?? '').trim();
  const password = String(req.body.password ?? '');
  const confirmPassword = req.body.confirmPassword;
  const wa = String(req.body.wa ?? '').replace(/[^0-9+]/g, '');

  if (!registerLimiter(req.ip)) return res.render('pages/register', { error: 'Terlalu banyak pendaftaran dari jaringan ini. Coba lagi nanti.' });
  if (!username || !password || !wa) {
    return res.render('pages/register', { error: 'Semua field wajib diisi' });
  }
  if (!/^[A-Za-z0-9_.-]{3,24}$/.test(username)) return res.render('pages/register', { error: 'Username 3-24 karakter: huruf, angka, titik, strip, atau underscore.' });
  if (password.length < 6 || password.length > 72) return res.render('pages/register', { error: 'Password harus 6-72 karakter.' });
  if (wa.length < 8 || wa.length > 20) return res.render('pages/register', { error: 'Nomor WhatsApp tidak valid.' });

  if (confirmPassword && password !== confirmPassword) {
    return res.render('pages/register', { error: 'Konfirmasi password tidak cocok' });
  }

  const lowerName = username.toLowerCase();
  if (lowerName === 'admin' || lowerName === String(readDB('settings.json').adminUsername || '').trim().toLowerCase()) {
    return res.render('pages/register', { error: 'Username tidak diizinkan' });
  }

  const users = await readFresh('users.json'); // fresh: cegah user baru saling menimpa antar-instance

  if (users.find(u => String(u.username).toLowerCase() === lowerName)) {
    return res.render('pages/register', { error: 'Username sudah digunakan' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(),
    username,
    password: hashedPassword,
    wa,
    photo: null,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  await writeDB('users.json', users);

  req.session.userId = newUser.id;
  req.session.isAdmin = false;

  res.redirect('/');
});

app.get('/logout', async (req, res) => {
  if (req.session?.isAdmin && req.session?.adminSessionId) {
    await releaseAdminLock(req.session.adminSessionId);
  }
  req.session = null;
  res.redirect('/');
});

// ══ Luxzco: ADMIN SECRET LOGIN GATE (hidden from public) ══
app.get('/lx-secure-panel-7k', (req, res) => {
  if (req.session?.isAdmin) return res.redirect('/admin');
  const kicked = req.query.kicked === '1';
  res.render('pages/admin-login', {
    error: kicked ? 'Anda logout otomatis karena ada login admin dari perangkat lain.' : null,
    lockedInfo: null,
    username: '',
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null
  });
});

app.post('/lx-secure-panel-7k', async (req, res) => {
  const ip = req.ip;
  const renderLogin = (error, extra = {}) => res.render('pages/admin-login', {
    error, lockedInfo: null, username: '', turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null, ...extra
  });

  const { blocked, wait } = checkLoginBlocked(ip);
  if (blocked) return renderLogin(`Terlalu banyak percobaan. Coba lagi dalam ${wait} menit.`);

  // Captcha (aktif otomatis bila TURNSTILE_* diisi) — rate limit in-memory tidak berbagi antar-instance Vercel,
  // jadi captcha inilah yang benar-benar menahan brute-force login admin.
  if (process.env.TURNSTILE_SECRET_KEY) {
    const tok = req.body['cf-turnstile-response'];
    if (!tok || !(await verifyTurnstile(String(tok)))) {
      return renderLogin('Verifikasi keamanan gagal. Selesaikan captcha lalu coba lagi.', { username: String(req.body.username || '').trim() });
    }
  }

  try {
    // Trim username (keyboard HP sering nambah spasi / kapital di awal, mis. "Admin ").
    // Password TIDAK di-trim: spasi di password itu sah.
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const forceTakeover = req.body.forceTakeover;

    // readFresh() ambil langsung dari Supabase, bypass cache (tiap instance Vercel punya cache sendiri)
    const settings = await db.readFresh('settings.json');

    if (!settings || !settings.adminUsername) {
      return renderLogin('Konfigurasi admin belum tersedia. Coba beberapa saat lagi.');
    }

    // Username: bandingkan tanpa peduli huruf besar/kecil & spasi ujung.
    const storedUser = String(settings.adminUsername).trim();
    const userOk = username.toLowerCase() === storedUser.toLowerCase();
    const passOk = !!password && !!settings.adminPassword
      ? await bcrypt.compare(password, settings.adminPassword)
      : false;

    if (userOk && passOk) {
      // ── Single-Device Lock: cek apakah panel sedang dipakai device lain ──
      const lockEnabled = settings.adminLockEnabled !== false; // default: aktif
      const currentLock = lockEnabled ? await db.readFresh('admin-lock.json') : null;
      if (lockEnabled && isLockActive(currentLock) && forceTakeover !== '1') {
        const minutesAgo = Math.max(1, Math.round((Date.now() - new Date(currentLock.lastSeen).getTime()) / 60000));
        return renderLogin(null, {
          username,
          lockedInfo: { device: currentLock.device || 'Perangkat tidak diketahui', minutesAgo }
        });
      }
      clearLoginFail(ip);
      req.session.userId = 'admin';
      req.session.isAdmin = true;
      req.session.adminSessionId = await acquireAdminLock(req);
      return res.redirect('/admin');
    }

    // DIAGNOSA (hanya ke log server, TIDAK ke browser): kasih tahu bagian mana yang salah
    // tanpa membocorkan nilai apa pun. Cek di Vercel → Logs / terminal lokal.
    console.warn(`[admin-login] GAGAL dari ${ip}: username ${userOk ? 'COCOK' : 'TIDAK cocok'}, password ${passOk ? 'cocok' : 'TIDAK cocok'}`
      + ` (input username ${username.length} char, password ${password.length} char; username tersimpan ${storedUser.length} char)`
      + (userOk && !passOk ? ' → hash di Supabase kemungkinan dari password lain. Jalankan: node reset-admin.js' : ''));

    recordLoginFail(ip);
    const remaining = LOGIN_MAX_FAIL - (loginFailMap.get(ip)?.count || 0);
    return renderLogin(
      remaining > 0
        ? `Username atau password salah. Sisa percobaan: ${remaining}`
        : 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.',
      { username }
    );
  } catch (err) {
    console.error('[admin-login] error:', err);
    return renderLogin('Terjadi kesalahan server saat login. Cek log server.');
  }
});


// ── RESELLER ──
app.get('/reseller', (req, res) => {
  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);
  res.render('pages/reseller', { layout: false, settings, user });
});

app.post('/reseller/join', requireAuth, async (req, res) => {
  try {
    if (req.session.isAdmin) return res.json({ success: false, message: 'Admin tidak perlu join reseller' });
    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    if (user.is_reseller) return res.json({ success: false, message: 'Kamu sudah menjadi Reseller VIP!' });

    const settings = readDB('settings.json');
    const price = settings.resellerPrice || 50000;
    const refId = uuidv4();
    const orderCode = generateOrderCode();

    let pay;
    try { pay = await createPayment(req, settings, { prefix: 'RES', price }); }
    catch (e) { return res.json({ success: false, message: e.plain ? 'Admin belum mengatur QRIS. Hubungi admin.' : e.message }); }
    const { orderId, qrString, isStatic, totalPayment, expiredAt, gateway } = pay;

    const transactions = await readFresh('transactions.json');
    transactions.push({
      id: refId, orderId, code: orderCode,
      userId: user.id, type: 'reseller',
      productName: 'Upgrade Reseller VIP',
      customerName: user.username, wa: user.wa,
      price, totalPayment, qrString, isStatic, gateway, expiredAt,
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic,
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ── PROFILE PHOTO ──
const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp/avatars' : path.join(__dirname, 'public', 'uploads', 'avatars');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `${req.session.userId}-${Date.now()}${safeExt(file.originalname)}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.post('/profile/photo', requireAuth, avatarUpload.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'File tidak valid' });

    // Admin tidak punya entry di users.json
    if (req.session.userId === 'admin') {
      return res.json({ success: false, message: 'Admin tidak bisa ganti foto profil dari sini' });
    }

    const users = await readFresh('users.json');
    const user  = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });

    // Hapus foto lama jika ada
    if (user.photo) {
      const oldPath = path.join(__dirname, 'public', user.photo.replace(/^\//, ''));
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }

    if (!isVercel) { user.photo = `/uploads/avatars/${req.file.filename}`; }
    else { try { user.photo = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch (e) { return res.json({ success: false, message: 'Upload gagal: ' + e.message }); } }
    await writeDB('users.json', users);
    res.json({ success: true, photo: user.photo });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ── BANNER CAROUSEL ──
const bannerCarouselUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp/banners' : path.join(__dirname, 'public', 'uploads', 'banners');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `banner-${Date.now()}${safeExt(file.originalname)}`);
    }
  }),
  limits: { fileSize: 4 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.get('/api/banners', async (req, res) => {
  // Admin panel butuh data paling baru setelah tambah/hapus banner → no-cache khusus admin.
  const isAdminReq = !!req.session?.isAdmin;
  const settings = isAdminReq ? await readFresh('settings.json') : await readSmart('settings.json');
  if (isAdminReq) res.set('Cache-Control', 'no-store'); else cachePublic(res, 60, 300);
  res.json((settings.banners || []).filter(b => b.active !== false));
});

app.post('/admin/banners/add', requireAdmin, bannerCarouselUpload.single('bannerImg'), async (req, res) => {
  try {
    const { title, subtitle, link, imageUrl } = req.body;
    const settings = await readFresh('settings.json');
    if (!settings.banners) settings.banners = [];
    let imgSrc = imageUrl?.trim() || '';
    if (req.file) {
      if (!isVercel) {
        imgSrc = `/uploads/banners/${req.file.filename}`;
      } else {
        try {
          imgSrc = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype);
        } catch (e) {
          // JANGAN fallback ke base64 di settings.json: settings dibaca di hampir semua
          // request, jadi 1 banner base64 (MBs) ikut ditarik dari Supabase berulang-ulang.
          return res.json({ success: false, message: 'Upload ke Supabase Storage gagal: ' + e.message + ' (pastikan bucket "product-images" sudah dibuat — jalankan supabase-schema.sql)' });
        }
      }
    }
    if (!imgSrc) return res.json({ success: false, message: 'Gambar banner wajib diisi' });
    settings.banners.push({
      id: uuidv4(),
      imageUrl: imgSrc,
      title: title?.trim() || '',
      subtitle: subtitle?.trim() || '',
      link: link?.trim() || '/',
      active: true,
      createdAt: new Date().toISOString()
    });
    await writeDB('settings.json', settings);
    res.json({ success: true, banners: settings.banners });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/banners/delete/:id', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const old = (settings.banners || []).find(b => b.id === req.params.id);
    if (old?.imageUrl?.startsWith('/uploads/banners/')) {
      const fp = path.join(__dirname, 'public', old.imageUrl);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    settings.banners = (settings.banners || []).filter(b => b.id !== req.params.id);
    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/banners/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const b = (settings.banners || []).find(b => b.id === req.params.id);
    if (b) b.active = !b.active;
    await writeDB('settings.json', settings);
    res.json({ success: true, active: b?.active });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// ── QRIS STATIS UPLOAD ──
const qrisUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp' : path.join(__dirname, 'public', 'uploads');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `qris-static${safeExt(file.originalname)}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.post('/admin/qris/upload', requireAdmin, qrisUpload.single('qrisImage'), async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'File tidak valid' });
    const settings = await readFresh('settings.json');
    if (!isVercel) {
      settings.qrisStaticImage = `/uploads/${req.file.filename}`;
    } else {
      try { settings.qrisStaticImage = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch (e) { return res.json({ success: false, message: e.message }); }
    }
    await writeDB('settings.json', settings);
    res.json({ success: true, path: settings.qrisStaticImage });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.get('/profile/me', requireAuth, (req, res) => {
  if (req.session.isAdmin) {
    const s = readDB('settings.json');
    return res.json({ success: true, user: { id: 'admin', username: s.adminUsername || 'Admin', isAdmin: true, is_reseller: false, photo: null } });
  }
  const users = readDB('users.json');
  const user  = users.find(u => u.id === req.session.userId);
  if (!user) return res.json({ success: false });
  const { password: _, ...safe } = user;
  res.json({ success: true, user: safe });
});

// ── User Dashboard ──
app.get('/dashboard', requireAuth, async (req, res) => {
  // readFresh: histori pembelian & key harus data terbaru dari Supabase,
  // bukan cache basi instance lambda ini (lihat catatan di /check-payment).
  // RPC: hanya transaksi milik user ini (bukan seluruh tabel); fallback ke cara lama bila RPC belum dibuat
  let myTransactions = await db.readUserTx(req.session.userId);
  if (!myTransactions) myTransactions = (await readFresh('transactions.json')).filter(t => t.userId === req.session.userId);
  const user = getSessionUser(req);
  const settings = readDB('settings.json');
  const totalOrders = myTransactions.length;
  const successOrders = myTransactions.filter(t => t.status === 'done').length;
  const pendingOrders = myTransactions.filter(t => t.status === 'pending').length;
  const totalSpent = myTransactions.filter(t => t.status === 'done').reduce((s, t) => s + (t.price || 0), 0);
  const doneTransactions = myTransactions.filter(t => t.status === 'done').sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const recentTransactions = myTransactions.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 20);

  res.render('pages/dashboard', {
    user, settings,
    stats: { totalOrders, successOrders, pendingOrders, totalSpent },
    doneTransactions: withDisplayTimeList(doneTransactions),
    transactions: withDisplayTimeList(recentTransactions)
  });
});

// Product routes
app.get('/buy/:id', requireAuth, async (req, res) => {
  // readSmart: cache <8 detik, tidak narik seluruh products.json (+semua key) tiap kunjungan
  const products = await readSmart('products.json');
  const rawProduct = products.find(p => p.id === req.params.id);
  if (rawProduct) await warmProviders([rawProduct]);

  if (!rawProduct || rawProduct.status !== 'active') {
    return res.redirect('/');
  }

  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);

  const isReseller = !!(user?.is_reseller);
  const resellerDiscount = settings.resellerDiscount || 20;

  // SECURITY: view TIDAK BOLEH menerima isi `keys` — hanya jumlah stok.
  // Juga bikin salinan baru (bukan memutasi objek di cache bersama).
  const { keys: rawKeys, gsMap: _gsMap, ...productBase } = rawProduct;
  const product = { ...productBase, stockCount: (rawKeys || []).length };
  if (rawProduct.items) {
    product.items = rawProduct.items.map(item => {
      const d = dur.parseDuration(item.l);
      const token = d ? dur.toToken(d.n, d.unit) : null;
      const local = countKeysForToken(rawKeys, token);
      const auto = local === 0 && !!token && gsAvailable(rawProduct, token);
      return {
        ...item,
        durLabel: d ? dur.displayLabel(d.n, d.unit) : item.l,
        stok: auto ? 999999 : local, // 999999 = tersedia otomatis (Infinity tidak aman di JSON)
        auto,
        reseller_price: isReseller ? Math.round(item.p * (1 - resellerDiscount / 100)) : null
      };
    });
    if (product.items.some(i => i.auto)) product.stockCount = Math.max(product.stockCount, 999999);
  }

  // Cek apakah user sudah pernah membeli (transaksi sukses) produk ini
  const transactions = readDB('transactions.json');
  const hasPurchased = transactions.some(t =>
    t.userId === user?.id &&
    t.productId === product.id &&
    t.status === 'done'
  );

  const _agg = { sum: 0, n: 0 };
  (readDB('testimonials.json') || []).forEach(t => {
    if ((t.productId || t.product) === product.id && t.verified && testiSource(t) === 'real' && t.rating >= 1 && t.rating <= 5) { _agg.sum += t.rating; _agg.n++; }
  });
  const ratingInfo = { avg: _agg.n ? Math.round((_agg.sum / _agg.n) * 10) / 10 : 0, count: _agg.n };

  res.render('pages/buy', { product, settings, user, isReseller, hasPurchased, ratingInfo });
});

// Buat pembayaran QRIS sesuai settings.qrisMode: 'static' | 'genspay' | (lainnya = PakKasir).
// Bila gateway error dan ada gambar QRIS statis → otomatis jatuh ke QRIS statis (konfirmasi manual admin).
const createPayment = async (req, settings, { prefix, price }) => {
  const mode = settings.qrisMode || 'static';
  const base = { isStatic: false, qrString: null, totalPayment: price, expiredAt: null, gateway: null, orderId: `${prefix}-${Date.now()}` };
  if (mode === 'static') {
    if (!settings.qrisStaticImage) { const e = new Error('Upload gambar QRIS di admin panel terlebih dahulu.'); e.plain = true; throw e; }
    return { ...base, isStatic: true };
  }
  try {
    if (mode === 'genspay') {
      const orderId = genspay.makeOrderId(prefix);
      const appUrl = (process.env.APP_URL || '').trim().replace(/\/+$/, '') || `${req.protocol}://${req.get('host')}`;
      const r = await genspay.createQris({ orderId, amount: price, callbackUrl: appUrl + '/webhook/genspay' });
      // expiry_time bisa berupa ISO / epoch detik / epoch ms → samakan ke ISO supaya timer di klien selalu benar
      let expISO = null;
      if (r.expiresAt != null) {
        const raw = r.expiresAt;
        const d = new Date(typeof raw === 'number' ? (raw < 1e12 ? raw * 1000 : raw) : (/^\d+$/.test(String(raw)) ? Number(raw) * (String(raw).length <= 10 ? 1000 : 1) : raw));
        if (!isNaN(d.getTime())) expISO = d.toISOString();
      }
      return { ...base, orderId, qrString: r.qrString, totalPayment: r.amount, expiredAt: expISO, gateway: 'genspay' };
    }
    const r = await createQRISPayment(base.orderId, price, settings);
    return { ...base, qrString: r.qr_string, totalPayment: r.total_payment || price, expiredAt: r.expired_at || null, gateway: 'pakasir' };
  } catch (error) {
    console.error(`[payment:${mode}] gagal:`, error.message);
    if (settings.qrisStaticImage) return { ...base, isStatic: true };
    throw new Error('QRIS API error: ' + error.message);
  }
};

app.post('/create-order', requireAuth, async (req, res) => {
  try {
    if (!orderLimiter(req.session.userId)) return res.json({ success: false, message: 'Terlalu banyak percobaan order. Tunggu beberapa menit.' });
    const { productId, duration } = req.body;
    const customerName = String(req.body.customerName ?? '').trim().slice(0, 60);
    const wa = String(req.body.wa ?? '').replace(/[^0-9+]/g, '').slice(0, 20);
    const voucherCode = req.body.voucherCode == null ? '' : String(req.body.voucherCode).slice(0, 40);
    if (typeof productId !== 'string') return res.json({ success: false, message: 'Produk tidak ditemukan' });
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === productId);

    if (!product || product.status !== 'active') return res.json({ success: false, message: 'Produk tidak ditemukan' });

    // Durasi: label item ("NAMA 3 HOURS" / "NAMA 7 DAYS"), atau angka/token ("30", "3h") dari klien lama.
    // Hari & jam dibedakan lewat selectedUnit supaya "3 jam" tidak pernah bentrok dengan "3 hari".
    const durStr = String(duration == null ? '' : duration).trim();
    const items = product.items || [];
    const itemMatch = items.find(i => i.l === durStr) || (durStr ? items.find(i => i.l.includes(durStr)) : null);
    const unitOf = (o) => (o.unit === 'hour' ? 'hour' : 'day');
    let price = 0, selectedDays = null, selectedUnit = 'day';
    if (itemMatch) {
      price = itemMatch.p;
      const parsed = dur.parseDuration(itemMatch.l);
      if (parsed) {
        selectedDays = parsed.n; selectedUnit = parsed.unit;
        const opt = (product.pricingOptions || []).find(o => o.days === parsed.n && unitOf(o) === parsed.unit);
        if (opt) price = opt.price; // pricingOptions = sumber harga resmi
      } else {
        const m = itemMatch.l.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null;
      }
    } else if (product.pricingOptions?.length) {
      const m = durStr.toLowerCase().match(/^(\d+)\s*(h|jam|hours?)?$/);
      const opt = m ? product.pricingOptions.find(o => o.days === parseInt(m[1]) && unitOf(o) === (m[2] ? 'hour' : 'day')) : null;
      if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
      price = opt.price; selectedDays = opt.days; selectedUnit = unitOf(opt);
    } else {
      return res.json({ success: false, message: 'Durasi tidak valid' });
    }

    // Stok PER DURASI: stok lokal (ber-tag durasi itu + generik) atau auto-restock Ghostseller.
    const token = dur.toToken(selectedDays, selectedUnit);
    if (countKeysForToken(product.keys, token) === 0) {
      const map = gsSellable(product, token) ? gsMappingFor(product, token) : null;
      if (!map) return res.json({ success: false, message: 'Stok habis' });
      if (!(await PROVIDERS[map.provider].isListed(map.productId, map.durationId))) {
        return res.json({ success: false, message: 'Paket ini sedang tidak tersedia. Coba lagi nanti.' });
      }
    }

    const settings = readDB('settings.json');
    // Terapkan diskon reseller
    const orderUser = getSessionUser(req);
    if (orderUser?.is_reseller) {
      const disc = settings.resellerDiscount || 20;
      price = Math.round(price * (1 - disc / 100));
    }

    // Terapkan voucher (setelah diskon reseller)
    let voucherDiscount = 0, appliedVoucher = null, originalPrice = price;
    if (voucherCode && voucherCode.trim()) {
      const vResult = await validateVoucher(voucherCode, price, req.session.userId);
      if (vResult.valid) {
        voucherDiscount = vResult.discount;
        price = vResult.finalPrice;
        appliedVoucher = vResult.voucher;
      } else {
        return res.json({ success: false, message: 'Voucher: ' + vResult.error });
      }
    }

    const transactions = await readFresh('transactions.json');
    compactTransactions(transactions);

    // Cegah transaksi duplikat (dicek SEBELUM membuat QR/transaksi di gateway supaya tidak ada transaksi gateway yatim)
    const existingPending = transactions.find(t =>
      t.userId === req.session.userId &&
      t.productId === productId &&
      t.status === 'pending' &&
      (Date.now() - new Date(t.createdAt).getTime()) < 30 * 60 * 1000
    );
    if (existingPending) {
      return res.json({ success: false, message: 'Kamu masih memiliki pesanan pending untuk produk ini. Selesaikan pembayaran atau tunggu 30 menit.' });
    }
    // Batasi total pesanan pending per user (cegah spam order lintas produk yang membengkakkan DB & QR gateway)
    const pendingCount = transactions.filter(t => t.userId === req.session.userId && t.status === 'pending' && (Date.now() - new Date(t.createdAt).getTime()) < 30 * 60 * 1000).length;
    if (pendingCount >= 5) return res.json({ success: false, message: 'Terlalu banyak pesanan pending. Selesaikan atau tunggu 30 menit.' });

    let pay;
    try { pay = await createPayment(req, settings, { prefix: 'LX', price }); }
    catch (e) { return res.json({ success: false, message: e.message }); }
    const { orderId, qrString, isStatic, totalPayment, expiredAt, gateway } = pay;
    const refId = uuidv4();
    const orderCode = generateOrderCode();

    transactions.push({
      id: refId, orderId, code: orderCode,
      userId: req.session.userId, productId: product.id, productName: product.name,
      duration: durStr, selectedDays, selectedUnit,
      originalPrice: voucherDiscount > 0 ? originalPrice : undefined,
      voucherCode: appliedVoucher ? appliedVoucher.code : undefined,
      voucherDiscount: voucherDiscount > 0 ? voucherDiscount : undefined,
      price, totalPayment,
      customerName, wa, qrString, isStatic, gateway, expiredAt,
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    // Catat pemakaian voucher jika dipakai
    if (appliedVoucher) {
      const vouchers = await readFresh('vouchers.json');
      const v = vouchers.find(v => v.id === appliedVoucher.id);
      if (v) {
        v.usedCount = (v.usedCount || 0) + 1;
        v.usages = v.usages || [];
        v.usages.push({ userId: req.session.userId, usedAt: new Date().toISOString(), orderId: refId });
        await writeDB('vouchers.json', vouchers);
      }
    }

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic, totalPayment, expiredAt,
      voucherDiscount: voucherDiscount || undefined,
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (error) {
    console.error('[create-order] error:', error.message);
    res.json({ success: false, message: 'Terjadi kesalahan: ' + error.message });
  }
});

// Upgrade akun jadi Reseller VIP setelah pembayaran lunas (dipakai check-payment & webhook).
const upgradeToReseller = async (transaction, transactions) => {
  const users = await readFresh('users.json');
  const u = users.find(u => u.id === transaction.userId);
  if (u && !u.is_reseller) {
    u.is_reseller = true;
    u.role = 'reseller';
    u.reseller_since = new Date().toISOString();
    u.reseller_code = 'RSL-' + u.username.toUpperCase().slice(0, 4) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
    await writeDB('users.json', users);
  }
  transaction.status = 'done';
  transaction.paidAt = new Date().toISOString();
  delete transaction.qrString;
  await writeDB('transactions.json', transactions);
};

app.get('/check-payment/:refId', requireAuth, async (req, res) => {
  const refId = req.params.refId;
  // Cegah race condition: jika transaksi sedang diproses, kembalikan pending
  if (processingOrders.has(refId)) {
    return res.json({ success: true, status: 'pending' });
  }
  processingOrders.add(refId);
  try {
    // PENTING: pakai readFresh (bukan readDB) di sini. readDB cuma baca cache
    // in-memory instance lambda ini sendiri — di Vercel, tiap instance punya
    // cache terpisah. Kalau order dibuat di instance A lalu dicek dari instance
    // B, instance B bisa saja belum tahu transaksi itu ada / masih lihat stok
    // key yang belum berkurang, akibatnya key tidak pernah dikirim ke user
    // meskipun pembayaran sudah sukses. readFresh selalu ambil data terbaru
    // langsung dari Supabase supaya konsisten di semua instance.
    // ── Jalur hemat egress: baca 1 transaksi lewat RPC, bukan seluruh transactions.json ──
    // Polling tiap beberapa detik dulu menarik SELURUH tabel transaksi di setiap poll. Jalur ini hanya
    // menjawab kasus yang tidak perlu menulis; sisanya jatuh ke jalur lengkap di bawah (perilaku lama).
    const lite = await db.readTxBy('id', refId);
    if (lite === null) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    if (lite) {
      if (lite.userId !== req.session.userId && !req.session.isAdmin) {
        return res.status(403).json({ success: false, message: 'Tidak diizinkan mengakses transaksi ini' });
      }
      if (lite.status === 'done') {
        if (lite.type === 'reseller') return res.json({ success: true, status: 'done', type: 'reseller' });
        return res.json({ success: true, status: 'done', key: lite.key, code: lite.code });
      }
      if (lite.isStatic) return res.json({ success: true, status: 'pending_static' });
      const needsFulfil = lite.paymentConfirmed && lite.status === 'pending' && lite.type !== 'reseller';
      if (lite.gateway === 'genspay' && !needsFulfil) {
        let willExpire = false;
        if (lite.status === 'pending' && lite.expiredAt) {
          const raw = lite.expiredAt;
          const t = new Date(typeof raw === 'number' && raw < 1e12 ? raw * 1000 : raw).getTime();
          willExpire = Number.isFinite(t) && Date.now() > t + 10 * 60 * 1000;
        }
        if (!willExpire) return res.json({ success: true, status: lite.status });
      }
    }
    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.id === refId);
    if (!transaction) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });

    // SECURITY: cegah IDOR — pastikan transaksi ini benar milik user yang login
    // (sebelumnya siapa saja yang login bisa lihat key orang lain kalau tahu/tebak refId-nya)
    if (transaction.userId !== req.session.userId && !req.session.isAdmin) {
      return res.status(403).json({ success: false, message: 'Tidak diizinkan mengakses transaksi ini' });
    }

    if (transaction.status === 'done') {
      if (transaction.type === 'reseller') return res.json({ success: true, status: 'done', type: 'reseller' });
      return res.json({ success: true, status: 'done', key: transaction.key, code: transaction.code });
    }

    // Static QRIS: tunggu konfirmasi manual admin
    if (transaction.isStatic) return res.json({ success: true, status: 'pending_static' });

    const settings = await readFresh('settings.json');
    const doneResponse = (r) => r.status === 'done'
      ? { success: true, status: 'done', key: r.key, code: transaction.code, outOfStock: r.outOfStock }
      : { success: true, status: 'pending', delivering: true };

    // Sudah LUNAS di gateway tapi key belum terkirim (mis. Ghostseller sedang error sementara):
    // coba kirim lagi, dibatasi 1x/15 detik. idempotencyKey = kode order → tidak pernah terbit 2 key.
    if (transaction.paymentConfirmed && transaction.status === 'pending' && transaction.type !== 'reseller') {
      if (Date.now() - new Date(transaction.lastFulfillAt || 0).getTime() < FULFILL_RETRY_GAP_MS) {
        return res.json({ success: true, status: 'pending', delivering: true });
      }
      return res.json(doneResponse(await deliverPaidOrder(transaction, transactions, { settings })));
    }

    // GensPay tidak punya endpoint cek-status: pelunasan masuk lewat webhook (/webhook/genspay) yang
    // mengubah data di DB. Di sini cukup baca DB — tanpa memanggil gateway (hemat Vercel & Supabase).
    if (transaction.gateway === 'genspay') {
      if (transaction.status === 'pending' && transaction.expiredAt) {
        const raw = transaction.expiredAt;
        const t = new Date(typeof raw === 'number' && raw < 1e12 ? raw * 1000 : raw).getTime();
        if (Number.isFinite(t) && Date.now() > t + 10 * 60 * 1000) { // toleransi 10 menit untuk webhook yang terlambat
          transaction.status = 'expired';
          await writeDB('transactions.json', transactions);
        }
      }
      return res.json({ success: true, status: transaction.status });
    }

    let paid = false;
    try {
      const r = await checkPaymentStatus(transaction.orderId, transaction.totalPayment || transaction.price, settings);
      // Normalize status dari berbagai format response PakKasir
      const status = (r.transaction?.status || r.status || r.data?.status || '').toLowerCase();
      // SECURITY: lunas HANYA bila status eksplisit lunas. Dulu ada `|| r.success === true`, sehingga respons
      // "sukses" apa pun (mis. transaksi masih pending) dianggap lunas dan key terkirim tanpa pembayaran.
      paid = ['completed','success','paid','settlement','capture','complete','authorize','accepted'].includes(status);
      const paidAmt = Number(r.transaction?.amount ?? r.data?.amount);
      if (paid && Number.isFinite(paidAmt) && paidAmt > 0 && paidAmt < Number(transaction.price)) paid = false;
      if (['expired','canceled','cancelled'].includes(status)) {
        transaction.status = 'expired';
        await writeDB('transactions.json', transactions);
        return res.json({ success: true, status: 'expired' });
      }
    } catch(e) { /* API error, keep pending */ }

    if (paid) {
      // Jika transaksi reseller, upgrade status user
      if (transaction.type === 'reseller') {
        await upgradeToReseller(transaction, transactions);
        return res.json({ success: true, status: 'done', type: 'reseller' });
      }

      // Re-ambil transaksi paling fresh sekali lagi tepat sebelum alokasi key —
      // mengecilkan window race kalau ada 2 polling nyaris bersamaan dari 2 instance.
      const transactionsRecheck = await readFresh('transactions.json');
      const freshTx = transactionsRecheck.find(t => t.id === refId) || transaction;
      if (freshTx.status === 'done') {
        if (freshTx.type === 'reseller') return res.json({ success: true, status: 'done', type: 'reseller' });
        return res.json({ success: true, status: 'done', key: freshTx.key, code: freshTx.code });
      }
      return res.json(doneResponse(await deliverPaidOrder(freshTx, transactionsRecheck, { settings })));
    }

    res.json({ success: true, status: transaction.status });
  } catch (error) {
    console.error('[check-payment] error:', error.message);
    res.json({ success: false, message: error.message });
  } finally {
    processingOrders.delete(refId);
  }
});

app.get(['/invoice','/cek-pesanan'], async (req, res) => {
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/invoice', { transaction: null, error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  const code = typeof req.query.code === 'string' ? req.query.code.trim() : '';
  if (code) {
    const transaction = await findTxByCode(code);
    return res.render('pages/invoice', { transaction: transaction ? withDisplayTime(transaction) : null, error: transaction ? null : 'Pesanan tidak ditemukan' });
  }
  res.render('pages/invoice', { transaction: null, error: null });
});

app.post(['/invoice','/cek-pesanan'], async (req, res) => {
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/invoice', { transaction: null, error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  const code = String(req.body.code || '').trim();
  if (!code) return res.render('pages/invoice', { transaction: null, error: 'Masukkan kode pesanan' });
  const transaction = await findTxByCode(code);

  if (!transaction) {
    return res.render('pages/invoice', { transaction: null, error: 'Pesanan tidak ditemukan' });
  }

  res.render('pages/invoice', { transaction: withDisplayTime(transaction), error: null });
});

// Admin routes
// Heartbeat dari tab admin yang masih terbuka — requireAdmin di atasnya
// sudah otomatis menolak (sessionRevoked) kalau lock sudah diambil device
// lain, dan otomatis memperpanjang lastSeen kalau masih sah.
app.post('/admin/session/heartbeat', requireAdmin, (req, res) => {
  res.json({ success: true });
});

// Status koneksi Supabase, dipakai widget "Status Database" di Settings.
// BUG SEBELUMNYA: frontend sudah fetch('/admin/db-status') tapi route ini
// belum pernah didaftarkan → selalu 404 → ketangkep catch(e){} kosong di
// frontend → teks "Memeriksa koneksi..." nyangkut selamanya, padahal
// koneksi Supabase-nya sendiri sebenarnya baik-baik saja.
app.get('/admin/db-status', requireAdmin, async (req, res) => {
  try {
    const status = await db.getDbStatus();
    res.json(status);
  } catch (e) {
    res.json({ connected: false, errorMsg: e.message });
  }
});

app.get('/admin', requireAdmin, async (req, res) => {
  // ── FIX: readFresh() bypass cache per-instance Vercel ──
  // Sebelumnya pakai readDB (cache lokal tiap instance), jadi setelah
  // tambah/edit produk di satu instance, refresh halaman bisa nyasar ke
  // instance lain yang cache-nya masih lama → produk kelihatan hilang/berubah.
  const [products, transactions, users, settings] = await Promise.all([
    readFresh('products.json'),
    readFresh('transactions.json'),
    readFresh('users.json'),
    readFresh('settings.json')
  ]);

  const stats = {
    totalProducts: products.length,
    activeProducts: products.filter(p => p.status === 'active').length,
    totalTransactions: transactions.length,
    pendingTransactions: transactions.filter(t => t.status === 'pending').length,
    doneTransactions: transactions.filter(t => t.status === 'done').length,
    totalUsers: users.length,
    totalResellers: users.filter(u => u.is_reseller).length,
    totalRevenue: transactions.filter(t => t.status === 'done').reduce((sum, t) => sum + t.price, 0)
  };

  // Data chart: 7 hari terakhir — dikelompokkan berdasarkan kalender WIB
  // (bukan UTC), supaya transaksi jam 00:00-06:59 WIB tidak salah masuk
  // ke hari sebelumnya. Indonesia tidak pakai DST jadi aman kurangi per
  // 24 jam pasti.
  const chartData = [];
  const nowMs = Date.now();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(nowMs - i * 86400000);
    const dateStr = jakartaDateKey(d);
    const dayTrx = transactions.filter(t => t.status === 'done' && t.createdAt && jakartaDateKey(t.createdAt) === dateStr);
    chartData.push({
      date: jakartaDayLabel(d),
      count: dayTrx.length,
      revenue: dayTrx.reduce((s, t) => s + t.price, 0)
    });
  }

  res.render('pages/admin', {
    layout: false,
    products,
    transactions: withDisplayTimeList(transactions.slice(-20).reverse()),
    users: users.map(({ password: _pw, ...u }) => u), // hash password tidak perlu sampai ke browser
    settings: maskSettingsForAdmin(settings),
    stats,
    chartData
  });
});

// Helper: parse pricingOptions. `units` (opsional, paralel dgn days): 'hour' = jam, selain itu = hari.
// Field `days` menyimpan JUMLAH dalam satuan `unit` (nama dipertahankan agar data lama tetap valid).
const toArr = (v) => Array.isArray(v) ? v : (v !== undefined && v !== null && v !== '' ? [v] : []);
function parsePricingOptions(days, prices, units) {
  const da = toArr(days), pa = toArr(prices), ua = toArr(units);
  const opts = []; const seen = new Set();
  for (let i = 0; i < da.length; i++) {
    const d = parseInt(da[i]), pr = parseInt(pa[i]);
    const unit = ua[i] === 'hour' ? 'hour' : 'day';
    const k = unit + ':' + d;
    if (d > 0 && pr >= 0 && !seen.has(k)) { seen.add(k); opts.push({ days: d, unit, price: pr }); }
  }
  return opts.sort((a, b) => dur.totalHours(a.days, a.unit) - dur.totalHours(b.days, b.unit));
}
const normalizePricingOptions = (list) => parsePricingOptions(
  (list || []).map(o => o.days), (list || []).map(o => o.price), (list || []).map(o => o.unit)
);

// Helper: validasi URL gambar (cegah XSS via javascript:/data: protocol)
const isValidImageUrl = (url) => {
  if (!url) return true;
  const lower = url.toLowerCase().trim();
  return !lower.startsWith('javascript:') && !lower.startsWith('data:') && !lower.startsWith('vbscript:');
};

app.post('/admin/product/add', requireAdmin, (req, res, next) => {
  upload.single('image')(req, res, err => {
    if (err) return res.json({ success: false, message: 'Upload error: ' + err.message });
    next();
  });
}, async (req, res) => {
  try {
    const {name,category,description,installUrl,imageUrl:imgUrl,pricingDays,pricingPrices,pricingUnits,keys,status}=req.body;
    if(!name)return res.json({success:false,message:'Nama produk wajib diisi'});
    if(imgUrl && !isValidImageUrl(imgUrl)) return res.json({success:false,message:'URL gambar tidak valid'});
    const products=await readFresh('products.json');
    const pricingOptions=parsePricingOptions(pricingDays,pricingPrices,pricingUnits);
    if(!pricingOptions.length)return res.json({success:false,message:'Tambahkan minimal 1 opsi harga'});
    const keyArray=keys?keys.split('\n').map(k=>k.trim()).filter(k=>k):[];
    let image = imgUrl?.trim() || '';
    if (req.file) {
      if (!isVercel) {
        image = `/uploads/products/${req.file.filename}`;
      } else {
        try {
          image = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype);
        } catch (e) {
          // Dulu error ditelan & produk tersimpan "sukses" dengan gambar placeholder yang tidak ada → gambar kosong tanpa kabar.
          if (imgUrl?.trim()) image = imgUrl.trim();
          else return res.json({ success: false, message: 'Upload gambar gagal: ' + e.message });
        }
      }
    }
    if (!image) image = '/images/placeholder.jpg';
    const items=pricingOptions.map(o=>({l:dur.itemLabel(name,o.days,o.unit),p:o.price}));
    const newProduct={id:uuidv4(),name,category:category||'freefire',description:description||'',installUrl:/^https?:\/\//i.test(String(installUrl||'').trim())?String(installUrl).trim().slice(0,500):'',image,pricingOptions,items,status:status==='inactive'?'inactive':'active',keys:keyArray,sold:0,createdAt:new Date().toISOString()};
    products.push(newProduct);await writeDB('products.json',products);
    res.json({success:true,product:newProduct});
  }catch(error){res.json({success:false,message:error.message});}
});

app.post('/admin/product/edit/:id', requireAdmin, (req, res, next) => {
  upload.single('image')(req, res, err => {
    if (err) return res.json({ success: false, message: 'Upload error: ' + err.message });
    next();
  });
}, async (req, res) => {
  try {
    const {name,category,description,installUrl,imageUrl:imgUrl,pricingDays,pricingPrices,pricingUnits,keys,keysMode,status}=req.body;
    const products=await readFresh('products.json');
    const product=products.find(p=>p.id===req.params.id);
    if(!product)return res.json({success:false,message:'Produk tidak ditemukan'});
    if(imgUrl && !isValidImageUrl(imgUrl)) return res.json({success:false,message:'URL gambar tidak valid'});
    if(name)product.name=name;if(category)product.category=category;
    if(description!==undefined)product.description=description;if(installUrl!==undefined)product.installUrl=/^https?:\/\//i.test(String(installUrl).trim())?String(installUrl).trim().slice(0,500):'';if(status)product.status=status;
    if(pricingDays){const opts=parsePricingOptions(pricingDays,pricingPrices,pricingUnits);if(opts.length){product.pricingOptions=opts;product.items=opts.map(o=>({l:dur.itemLabel(product.name,o.days,o.unit),p:o.price}));}}
    if(keys!==undefined&&keys!==null){const nk=keys.split('\n').map(k=>k.trim()).filter(k=>k);product.keys=keysMode==='append'?[...(product.keys||[]),...nk]:nk;}
    if (req.file) {
      if (!isVercel) product.image=`/uploads/products/${req.file.filename}`;
      else { try { product.image = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch (e) { return res.json({ success: false, message: 'Upload gambar gagal: ' + e.message }); } }
    }
    else if(imgUrl?.trim()) product.image=imgUrl.trim();
    await writeDB('products.json',products);res.json({success:true,product});
  }catch(error){res.json({success:false,message:error.message});}
});

app.post('/admin/product/keys/:id', requireAdmin, async (req, res) => {
  try {
    const{keys,mode}=req.body;const products=await readFresh('products.json');
    const product=products.find(p=>p.id===req.params.id);
    if(!product)return res.json({success:false,message:'Produk tidak ditemukan'});
    const nk=(keys||'').split('\n').map(k=>k.trim()).filter(k=>k);
    product.keys=mode==='replace'?nk:[...(product.keys||[]),...nk];
    await writeDB('products.json',products);res.json({success:true,keyCount:product.keys.length});
  }catch(e){res.json({success:false,message:e.message});}
});

app.post('/admin/product/delete/:id', requireAdmin, async (req, res) => {
  try {
    let products = await readFresh('products.json');
    products = products.filter(p => p.id !== req.params.id);
    await writeDB('products.json', products);
    res.json({ success: true, message: 'Produk berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/user/delete/:id', requireAdmin, async (req, res) => {
  try {
    let users = await readFresh('users.json');
    users = users.filter(u => u.id !== req.params.id);
    await writeDB('users.json', users);
    res.json({ success: true, message: 'User berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/transaction/delete/:id', requireAdmin, async (req, res) => {
  try {
    let transactions = await readFresh('transactions.json');
    transactions = transactions.filter(t => t.id !== req.params.id);
    await writeDB('transactions.json', transactions);
    res.json({ success: true, message: 'Transaksi berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/transaction/status/:id', requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const transactions = await readFresh('transactions.json');
    const trx = transactions.find(t => t.id === req.params.id);
    if (!trx) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    trx.status = status;
    trx.updatedBy = 'admin';
    trx.updatedAt = new Date().toISOString();
    await writeDB('transactions.json', transactions);
    res.json({ success: true, message: 'Status berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/product/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === req.params.id);

    if (!product) {
      return res.json({ success: false, message: 'Produk tidak ditemukan' });
    }

    product.status = product.status === 'active' ? 'inactive' : 'active';
    await writeDB('products.json', products);

    res.json({ success: true, message: 'Status produk berhasil diubah', status: product.status });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/product/add-keys/:id', requireAdmin, async (req, res) => {
  try {
    const { keys } = req.body;
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === req.params.id);

    if (!product) {
      return res.json({ success: false, message: 'Produk tidak ditemukan' });
    }

    const newKeys = keys.split('\n').map(k => k.trim()).filter(k => k);
    product.keys = product.keys || [];
    product.keys.push(...newKeys);

    await writeDB('products.json', products);
    res.json({ success: true, message: `${newKeys.length} key berhasil ditambahkan`, keyCount: product.keys.length });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/update', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { siteName, gamePanelName, about, marqueeText, whatsapp, telegram, waChannel, tiktok, email, adminUsername, categories, categoryLabels, logoUrl, fonnteToken } = req.body;

    if (siteName)      settings.siteName      = siteName;
    if (gamePanelName) settings.gamePanelName = gamePanelName;
    if (about !== undefined) settings.about   = about;
    if (marqueeText)   settings.marqueeText   = marqueeText;
    if (adminUsername) settings.adminUsername = adminUsername;
    if (logoUrl !== undefined) settings.logoUrl = logoUrl;
    if (fonnteToken !== undefined && !isMaskedSecret(fonnteToken)) settings.fonnteToken = fonnteToken; // nilai bertopeng = tidak diubah

    settings.contact = settings.contact || {};
    if (whatsapp !== undefined) settings.contact.whatsapp = whatsapp;
    if (telegram !== undefined) settings.contact.telegram = String(telegram).replace(/^@/, '').replace(/^https?:\/\/t\.me\//i, '').trim();
    if (waChannel !== undefined) settings.contact.waChannel = String(waChannel).replace(/^https?:\/\/whatsapp\.com\/channel\//i, '').trim();
    if (tiktok !== undefined) settings.contact.tiktok = String(tiktok).replace(/^@/, '').replace(/^https?:\/\/(www\.)?tiktok\.com\/@/i, '').trim();
    if (email    !== undefined) settings.contact.email    = email;

    // Handle categories update from JSON string or array
    if (categories) {
      try {
        settings.categories = JSON.parse(categories);
      } catch(e) {
        if (Array.isArray(categories)) settings.categories = categories;
      }
    }
    if (categoryLabels) {
      try {
        settings.categoryLabels = JSON.parse(categoryLabels);
      } catch(e) {
        if (typeof categoryLabels === 'object') settings.categoryLabels = categoryLabels;
      }
    }

    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Pengaturan berhasil diupdate' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// Ganti mode pembayaran. Whitelist ketat; TIDAK menyentuh kredensial apa pun.
app.post('/admin/settings/qris-mode', requireAdmin, async (req, res) => {
  try {
    const mode = String(req.body.qrisMode || '');
    if (!['static', 'api', 'genspay'].includes(mode)) return res.json({ success: false, message: 'Mode tidak valid' });
    const settings = await readFresh('settings.json');
    settings.qrisMode = mode;
    await writeDB('settings.json', settings);
    res.json({ success: true, qrisMode: mode, genspayReady: genspay.isConfigured() });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Tes koneksi GensPay: membuat 1 transaksi uji Rp1.000 (otomatis EXPIRED, tidak ditagih). Key tidak pernah ditampilkan.
app.post('/admin/settings/genspay-test', requireAdmin, async (req, res) => {
  if (!genspay.isConfigured()) return res.json({ success: false, message: 'GENSPAY_API_KEY belum diisi di environment (Vercel → Settings → Environment Variables), lalu Redeploy.' });
  const appUrl = (process.env.APP_URL || '').trim().replace(/\/+$/, '') || `${req.protocol}://${req.get('host')}`;
  try {
    await genspay.createQris({ orderId: genspay.makeOrderId('TEST'), amount: genspay.MIN_AMOUNT, callbackUrl: appUrl + '/webhook/genspay' });
    res.json({ success: true, message: 'Terhubung ✔ API key diterima, transaksi uji dibuat (akan kedaluwarsa sendiri).', webhookUrl: appUrl + '/webhook/genspay', appUrlSet: !!process.env.APP_URL });
  } catch (e) {
    res.json({ success: false, message: 'GensPay: ' + e.message });
  }
});

// Katalog provider auto-restock (server-side; API key/token tidak pernah sampai ke browser). ?provider=ghostseller|dripstore
app.get('/admin/autorestock/catalog', requireAdmin, async (req, res) => {
  const prov = PROVIDERS[String(req.query.provider || 'ghostseller')];
  if (!prov) return res.json({ success: false, message: 'Provider tidak dikenal' });
  if (!prov.isConfigured()) {
    const envName = prov.name === 'dripstore' ? 'DRIPSTORE_API_TOKEN' : 'GHOSTSELLER_API_KEY';
    return res.json({ success: false, message: `${envName} belum diisi di environment (Vercel → Settings → Environment Variables), lalu Redeploy.` });
  }
  try {
    const products = await prov.fetchCatalog({ force: req.query.refresh === '1' });
    let balance = null;
    if (prov.getBalance) { try { balance = await prov.getBalance({ force: req.query.refresh === '1' }); } catch { /* saldo opsional */ } }
    res.json({ success: true, provider: prov.name, products, balance });
  } catch (e) {
    res.json({ success: false, code: e.code, message: (GS_REASON_TEXT[e.code] || e.message) });
  }
});

// Probe Drip Store dari server (Vercel): mengumpulkan contoh respons + menunjukkan apakah IP server diterima Cloudflare.
// Baca-saja, tidak memotong saldo; token & isi key disamarkan. Dibatasi 1x/15 dtk (rate limit provider 60 req/menit).
let lastProbeAt = 0;
app.post('/admin/autorestock/probe', requireAdmin, async (req, res) => {
  if (Date.now() - lastProbeAt < 15000) return res.json({ success: false, message: 'Tunggu ±15 detik sebelum probe lagi.' });
  lastProbeAt = Date.now();
  try {
    res.json({ success: true, report: await dripstore.probe() });
  } catch (e) {
    res.json({ success: false, message: GS_REASON_TEXT[e.code] || e.message });
  }
});

// Simpan mapping durasi produk ini → durasi/varian provider.
// body: { provider, productId, durations: { '<token>': '<id>' } }   productId kosong = hapus mapping (stok lokal saja).
app.post('/admin/product/:id/gs-map', requireAdmin, async (req, res) => {
  try {
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === req.params.id);
    if (!product) return res.json({ success: false, message: 'Produk tidak ditemukan' });
    const provName = String(req.body.provider || 'ghostseller');
    const prov = PROVIDERS[provName];
    if (!prov) return res.json({ success: false, message: 'Provider tidak dikenal' });
    const gsProductId = String(req.body.productId || '').trim().slice(0, 120);
    if (!gsProductId) { delete product.gsMap; await writeDB('products.json', products); return res.json({ success: true, cleared: true }); }

    const durations = {};
    for (const [token, durationId] of Object.entries(req.body.durations || {})) {
      if (!/^\d{1,5}h?$/.test(token)) continue;
      const id = String(durationId || '').trim().slice(0, 120);
      if (id) durations[token] = id;
    }
    // Validasi ke katalog bila terjangkau (cegah salah ketik id / varian yang butuh Android ID)
    if (prov.isConfigured()) {
      try {
        const cat = await prov.fetchCatalog();
        const gp = cat.find(x => x.id === gsProductId);
        if (!gp) return res.json({ success: false, message: 'Produk itu tidak ditemukan di katalog provider.' });
        for (const [t, id] of Object.entries(durations)) {
          const d = gp.durations.find(d => d.id === id);
          if (!d) return res.json({ success: false, message: `Varian "${id}" (untuk ${t}) tidak ada di produk provider itu.` });
          if (d.unsupported) return res.json({ success: false, message: `Varian "${d.label}" tidak didukung: ${d.unsupported}.` });
        }
      } catch { /* katalog tak terjangkau: simpan saja, divalidasi lagi saat order */ }
    }
    product.gsMap = { provider: provName, productId: gsProductId, durations, updatedAt: new Date().toISOString() };
    await writeDB('products.json', products);
    res.json({ success: true, gsMap: product.gsMap });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/settings/pakasir', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { apiKey, project, mode, apiBaseUrl, qrisMode } = req.body;

    settings.pakasir = {
      apiKey: (apiKey !== undefined && !isMaskedSecret(apiKey)) ? apiKey : (settings.pakasir?.apiKey || ''),
      project: project !== undefined ? project : (settings.pakasir?.project || ''),
      mode: mode || settings.pakasir?.mode || 'production',
      apiBaseUrl: apiBaseUrl !== undefined ? apiBaseUrl : (settings.pakasir?.apiBaseUrl || 'api.pakasir.com')
    };

    if (qrisMode && ['static', 'api', 'genspay'].includes(qrisMode)) settings.qrisMode = qrisMode;

    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/qris/test', requireAdmin, async (req, res) => {
  try {
    const { project, apiBaseUrl } = req.body;
    let apiKey = req.body.apiKey;
    if (isMaskedSecret(apiKey)) apiKey = (await readFresh('settings.json')).pakasir?.apiKey || '';
    const hostname = apiBaseUrl || 'api.pakasir.com';
    const testSettings = { pakasir: { apiKey, project, apiBaseUrl: hostname } };
    try {
      await createQRISPayment('test-' + Date.now(), 1000, testSettings);
      res.json({ success: true });
    } catch (e) {
      res.json({ success: false, message: e.message });
    }
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/password', requireAdmin, async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      return res.json({ success: false, message: 'Password minimal 6 karakter' });
    }

    const settings = await readFresh('settings.json');
    settings.adminPassword = await bcrypt.hash(newPassword, 12);

    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Password admin berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/admin-lock', requireAdmin, async (req, res) => {
  try {
    const { adminLockEnabled } = req.body;
    const settings = await readFresh('settings.json');
    settings.adminLockEnabled = adminLockEnabled === 'true' || adminLockEnabled === true;
    await writeDB('settings.json', settings);
    res.json({ success: true, adminLockEnabled: settings.adminLockEnabled });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/settings/reseller', requireAdmin, async (req, res) => {
  try {
    const { resellerEnabled, resellerPrice, resellerDiscount, resellerNote } = req.body;
    const settings = await readFresh('settings.json');
    settings.resellerEnabled = resellerEnabled === 'true' || resellerEnabled === true;
    if (resellerPrice !== undefined && resellerPrice !== '') {
      const price = parseInt(resellerPrice);
      if (isNaN(price) || price < 0) return res.json({ success: false, message: 'Harga reseller tidak valid' });
      settings.resellerPrice = price;
    }
    if (resellerDiscount !== undefined && resellerDiscount !== '') {
      const discount = parseInt(resellerDiscount);
      if (isNaN(discount) || discount < 0 || discount > 100) return res.json({ success: false, message: 'Diskon harus antara 0-100%' });
      settings.resellerDiscount = discount;
    }
    if (resellerNote !== undefined) settings.resellerNote = resellerNote;
    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/user/toggle-reseller/:id', requireAdmin, async (req, res) => {
  try {
    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    user.is_reseller = !user.is_reseller;
    user.role = user.is_reseller ? 'reseller' : 'user';
    if (user.is_reseller) {
      user.reseller_since = user.reseller_since || new Date().toISOString();
      user.reseller_code = user.reseller_code || ('RSL-' + user.username.toUpperCase().slice(0, 4) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase());
    }
    await writeDB('users.json', users);
    res.json({ success: true, is_reseller: user.is_reseller });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Konfirmasi transaksi manual oleh admin (untuk QRIS statis atau reseller)
app.post('/admin/transaction/confirm/:id', requireAdmin, async (req, res) => {
  const lockId = 'confirm:' + req.params.id;
  if (processingOrders.has(lockId)) return res.json({ success: false, message: 'Konfirmasi sedang diproses, tunggu sebentar.' });
  processingOrders.add(lockId);
  try {
    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.id === req.params.id);
    if (!transaction) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    if (transaction.status === 'done') return res.json({ success: false, message: 'Transaksi sudah selesai' });

    // Jika transaksi reseller, upgrade user
    if (transaction.type === 'reseller') {
      const users = await readFresh('users.json');
      const u = users.find(u => u.id === transaction.userId);
      if (u) {
        u.is_reseller = true;
        u.role = 'reseller';
        u.reseller_since = u.reseller_since || new Date().toISOString();
        u.reseller_code = u.reseller_code || ('RSL-' + u.username.toUpperCase().slice(0, 4) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase());
        await writeDB('users.json', users);
      }
      transaction.status = 'done';
      transaction.paidAt = new Date().toISOString();
      await writeDB('transactions.json', transactions);
      return res.json({ success: true, type: 'reseller' });
    }

    // Transaksi produk biasa: alokasi key (stok lokal → Ghostseller). Selalu data FRESH (cache basi per-instance
    // Vercel bisa membuat 1 key terjual 2x). Fallback lama `keys.shift()` sudah dihapus: bisa mengirim key
    // berlabel durasi lain.
    const r = await deliverPaidOrder(transaction, transactions, { settings: null, confirmedBy: 'admin' });
    if (r.status === 'delivering') {
      return res.json({ success: false, message: 'Ghostseller sedang bermasalah sementara. Pembayaran sudah dicatat — coba klik Konfirmasi lagi dalam beberapa saat (tidak akan terbit 2 key).' });
    }
    if (!r.key) {
      // deliverPaidOrder menandai outOfStock; untuk konfirmasi manual, kembalikan ke pending agar admin bisa tambah stok & ulangi
      transaction.status = 'pending'; transaction.outOfStock = false; transaction.fulfillAttempts = 0;
      await writeDB('transactions.json', transactions);
      return res.json({ success: false, message: 'Key tidak tersedia: ' + (GS_REASON_TEXT[transaction.lastFulfillError] || 'stok kosong') + ' Tambah stok / perbaiki mapping Ghostseller di Admin → Produk, lalu konfirmasi lagi.' });
    }
    return res.json({ success: true, key: r.key, source: transaction.keySource });
  } catch (e) {
    res.json({ success: false, message: e.message });
  } finally {
    processingOrders.delete(lockId);
  }
});

// Leaderboard route
app.get('/leaderboard', (req, res) => {
  const transactions = readDB('transactions.json');
  const users = readDB('users.json');
  const settings = readDB('settings.json');

  // Calculate leaderboard
  const userStats = {};

  transactions.forEach(t => {
    if (t.status === 'done' && t.userId) {
      if (!userStats[t.userId]) {
        userStats[t.userId] = {
          userId: t.userId,
          totalTransactions: 0,
          totalSpent: 0
        };
      }
      userStats[t.userId].totalTransactions++;
      userStats[t.userId].totalSpent += t.price;
    }
  });

  // Convert to array and add user info
  const leaderboard = Object.values(userStats).map(stat => {
    const user = users.find(u => u.id === stat.userId);
    return {
      ...stat,
      username: user?.username || 'Unknown',
      photo: user?.photo || null
    };
  });

  // Sort by total transactions descending
  leaderboard.sort((a, b) => b.totalTransactions - a.totalTransactions);

  // Add rank
  leaderboard.forEach((item, index) => {
    item.rank = index + 1;
  });

  const user = getSessionUser(req);

  res.render('pages/leaderboard', {
    leaderboard,
    settings,
    user
  });
});

// API endpoints
app.get('/api/products', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan. Coba lagi nanti.' });
  const activeProducts = (await readSmart('products.json')).filter(p => p.status === 'active');
  await warmProviders(activeProducts);
  const products = activeProducts
    // SECURITY: jangan kirim keys ke publik — keys hanya dikirim setelah pembayaran sukses
    .map(withStockCount);
  cachePublic(res, 30);
  res.json(products);
});

// ── Helper: validasi & hitung diskon voucher ──
const validateVoucher = async (code, price, userId) => {
  if (!code) return { valid: false, error: 'Kode kosong' };
  const vouchers = await readFresh('vouchers.json');
  const v = vouchers.find(v => v.code.toUpperCase() === code.trim().toUpperCase());
  if (!v) return { valid: false, error: 'Kode voucher tidak ditemukan' };
  if (!v.active) return { valid: false, error: 'Voucher tidak aktif' };
  if (v.expiresAt && new Date(v.expiresAt) < new Date()) return { valid: false, error: 'Voucher sudah kadaluarsa' };
  if (v.maxUses > 0 && v.usedCount >= v.maxUses) return { valid: false, error: 'Voucher sudah habis digunakan' };
  if (v.minPurchase > 0 && price < v.minPurchase) return { valid: false, error: `Minimal pembelian Rp ${v.minPurchase.toLocaleString('id-ID')}` };
  if (v.perUserLimit > 0 && userId) {
    const userUses = (v.usages || []).filter(u => u.userId === userId).length;
    if (userUses >= v.perUserLimit) return { valid: false, error: 'Kamu sudah pernah memakai voucher ini' };
  }
  const discount = v.type === 'percent'
    ? Math.round(price * v.value / 100)
    : Math.min(v.value, price);
  const finalPrice = Math.max(price - discount, 0);
  return { valid: true, voucher: v, discount, finalPrice };
};

app.get('/api/stats', async (req, res) => {
  cachePublic(res, 60, 300);
  const products = await readSmart('products.json');
  const testimonials = await readSmart('testimonials.json');
  const users = readDB('users.json'); // cukup untuk hitung jumlah; tak perlu fetch ulang tabel user (berisi hash)
  const active = products.filter(p => p.status === 'active');
  const totalSold = products.reduce((s, p) => s + (p.sold || 0), 0);
  const avgRating = testimonials.length
    ? (testimonials.reduce((s, t) => s + (t.rating || 0), 0) / testimonials.length).toFixed(1)
    : '0.0';
  res.json({
    totalSold,
    totalActiveProducts: active.length,
    totalUsers: users.length,
    avgRating: parseFloat(avgRating)
  });
  // (cache CDN di bawah)
});

// Cek voucher (user)
app.post('/api/voucher/check', requireAuth, async (req, res) => {
  const { code, price } = req.body;
  if (!code || !price) return res.json({ valid: false, error: 'Data tidak lengkap' });
  const result = await validateVoucher(code, parseInt(price), req.session.userId);
  if (!result.valid) return res.json({ valid: false, error: result.error });
  res.json({
    valid: true,
    code: result.voucher.code,
    type: result.voucher.type,
    value: result.voucher.value,
    description: result.voucher.description || '',
    discount: result.discount,
    finalPrice: result.finalPrice
  });
});

app.get('/api/transactions', requireAdmin, (req, res) => {
  const transactions = readDB('transactions.json');
  res.json(withDisplayTimeList(transactions));
});

app.get('/api/testimonials', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan.' });
  const testimonials = await readSmart('testimonials.json');
  const users = await readSmart('users.json');
  const featured = req.query.featured === 'true';
  const verifiedOnly = req.query.verified === 'true';
  const productId = req.query.product;

  let filtered = testimonials;

  if (featured) {
    filtered = filtered.filter(t => t.featured && t.verified);
  } else if (verifiedOnly) {
    filtered = filtered.filter(t => t.verified);
  }

  if (productId) {
    filtered = filtered.filter(t => t.product === productId || t.productName === productId);
  }

  // Sort by date descending
  filtered.sort((a, b) => new Date(b.date) - new Date(a.date));

  // Attach user photo if available
  filtered = filtered.map(t => {
    const u = users.find(u => u.username === t.username);
    const { userId, ...safe } = t; // jangan bocorkan ID internal user ke publik
    return { ...safe, photo: u?.photo || null };
  });

  // Data 100% real dari database — tidak ada lagi padding testimoni palsu.
  const maxDisplay = 30;
  cachePublic(res, 30, 120);
  res.json(filtered.slice(0, maxDisplay));
});

app.post('/api/testimonials', requireAuth, async (req, res) => {
  try {
    const { productId, productName, rating, text } = req.body;
    if (!productId || !rating || !text) return res.json({ success: false, message: 'Data tidak lengkap' });
    const ratingNum = parseInt(rating);
    if (ratingNum < 1 || ratingNum > 5) return res.json({ success: false, message: 'Rating tidak valid' });
    if (!text.trim()) return res.json({ success: false, message: 'Ulasan tidak boleh kosong' });
    if (text.trim().length > 500) return res.json({ success: false, message: 'Ulasan maksimal 500 karakter' });

    // Hanya user yang sudah membeli (transaksi sukses/done) produk ini yang boleh kirim testimoni
    const transactions = await readFresh('transactions.json');
    const hasPurchased = transactions.some(t =>
      t.userId === req.session.userId &&
      t.productId === productId &&
      t.status === 'done'
    );
    if (!hasPurchased) {
      return res.json({ success: false, message: 'Hanya pembeli produk ini yang bisa memberikan rating/testimoni' });
    }

    const users = await readSmart('users.json');
    const user = users.find(u => u.id === req.session.userId);
    const testimonials = await readFresh('testimonials.json');

    testimonials.unshift({
      id: uuidv4(),
      source: 'real',
      userId: req.session.userId,
      productId,
      product: productId,
      productName: productName || '',
      username: user?.username || 'Pengguna',
      rating: ratingNum,
      text: text.trim(),
      date: new Date().toISOString(),
      verified: true,
      featured: false
    });

    await writeDB('testimonials.json', testimonials);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.get('/admin/testimonials/all', requireAdmin, async (req, res) => {
  const list = (await readFresh('testimonials.json'))
    .map(t => ({ ...t, source: testiSource(t), displayName: t.name || t.username || 'Pelanggan', displayProduct: t.productName || t.product || '' }))
    .sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
  res.json(list);
});

app.post('/admin/testimonial/add', requireAdmin, async (req, res) => {
  try {
    const { name, username, rating, text, product, verified, featured } = req.body;
    if (!String(name || '').trim() || !String(text || '').trim()) return res.json({ success: false, message: 'Nama dan isi testimoni wajib diisi' });
    const testimonials = await readFresh('testimonials.json');

    const newTestimonial = {
      id: `testi-${Date.now()}`,
      source: 'manual',
      name: String(name || '').trim().slice(0, 40),
      username: username || null,
      rating: parseInt(rating) || 5,
      text: String(text || '').trim().slice(0, 500),
      product: product || null,
      productName: product || '',
      date: new Date().toISOString(),
      verified: verified === true || verified === 'true',
      featured: featured === true || featured === 'true'
    };

    testimonials.push(newTestimonial);
    await writeDB('testimonials.json', testimonials);

    res.json({ success: true, message: 'Testimoni berhasil ditambahkan' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/delete/:id', requireAdmin, async (req, res) => {
  try {
    let testimonials = await readFresh('testimonials.json');
    testimonials = testimonials.filter(t => t.id !== req.params.id);
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: 'Testimoni berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/toggle-featured/:id', requireAdmin, async (req, res) => {
  try {
    const testimonials = await readFresh('testimonials.json');
    const testi = testimonials.find(t => t.id === req.params.id);
    if (!testi) return res.json({ success: false, message: 'Testimoni tidak ditemukan' });

    testi.featured = !testi.featured;
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: 'Status featured berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/toggle-verified/:id', requireAdmin, async (req, res) => {
  try {
    const testimonials = await readFresh('testimonials.json');
    const testi = testimonials.find(t => t.id === req.params.id);
    if (!testi) return res.json({ success: false, message: 'Testimoni tidak ditemukan' });

    testi.verified = !testi.verified;
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: testi.verified ? 'Testimoni berhasil diverifikasi' : 'Verifikasi dicabut' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.get('/api/notifications', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan.' });
  // readSmart: ambil langsung dari Supabase kalau cache instance ini sudah >8 detik,
  // supaya notifikasi selalu data transaksi asli & konsisten di semua instance Vercel,
  // bukan cache basi milik satu lambda instance saja.
  const all = await readSmart('notifications.json');
  const notifs = all.slice(0, 20);
  cachePublic(res, 30, 120); // data sudah dianonimkan → aman di-cache di CDN
  // SECURITY: anonimkan nama pembeli — hanya tampilkan initial agar tidak bocor daftar username asli
  const anonymize = (name = '') => {
    if (!name) return '***';
    return name[0] + '*'.repeat(Math.max(name.length - 1, 2));
  };
  const enriched = notifs.map(({ id, type, productName, price, timeStr, buyerName }) => ({
    id, type, productName, price, timeStr,
    buyerName: anonymize(buyerName),
    buyerPhoto: null
  }));
  res.json(enriched);
});

app.get('/api/leaderboard', (req, res) => {
  cachePublic(res, 60, 300);
  const transactions = readDB('transactions.json');
  const users = readDB('users.json');

  // Calculate real leaderboard
  const userStats = {};
  transactions.forEach(t => {
    if (t.status === 'done' && t.userId) {
      if (!userStats[t.userId]) userStats[t.userId] = { userId: t.userId, totalTransactions: 0, totalSpent: 0 };
      userStats[t.userId].totalTransactions++;
      userStats[t.userId].totalSpent += t.price;
    }
  });

  const realEntries = Object.values(userStats).map(stat => {
    const user = users.find(u => u.id === stat.userId);
    return { username: user?.username || 'User', totalTransactions: stat.totalTransactions, totalSpent: stat.totalSpent, isReal: true };
  });

  realEntries.sort((a, b) => b.totalTransactions - a.totalTransactions || b.totalSpent - a.totalSpent);
  realEntries.forEach((item, i) => { item.rank = i + 1; });

  res.json({ success: true, data: realEntries.slice(0, 10) });
});

// ═══════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════

// Admin Product Edit Page
app.get('/admin/product-edit', requireAdmin, async (req, res) => {
  const [products, settings] = await Promise.all([readFresh('products.json'), readFresh('settings.json')]);
  const productId = req.query.id;
  const product = productId ? products.find(p => p.id === productId) : null;
  res.render('pages/admin-product-edit', { product, products, settings: maskSettingsForAdmin(settings) });
});

// Admin Theme Settings Page
app.get('/admin/theme-settings', requireAdmin, async (req, res) => {
  const settings = await readFresh('settings.json');
  res.render('pages/admin-theme', { settings: maskSettingsForAdmin(settings) });
});

// Admin Product Management
app.get('/admin/products', requireAdmin, async (req, res) => {
  const products = await readFresh('products.json');
  res.json({ success: true, data: products });
});

// Admin Get Single Product
app.get('/admin/product/:id', requireAdmin, async (req, res) => {
  const products = await readFresh('products.json');
  const product = products.find(p => p.id === req.params.id);
  if (!product) return res.json({ success: false, message: 'Produk tidak ditemukan' });
  res.json({ success: true, data: product });
});

// Admin Update Product (image, status, keys)
app.post('/admin/product/:id', requireAdmin, async (req, res) => {
  try {
    const { items, bannerUrl, status, keys, keysMode, platforms, description, installUrl } = req.body;
    const products = await readFresh('products.json');
    const productIndex = products.findIndex(p => p.id === req.params.id);

    if (productIndex === -1) return res.json({ success: false, message: 'Produk tidak ditemukan' });
    const p = products[productIndex];

    // Simpan ke image (yang dibaca frontend) DAN bannerUrl
    if (bannerUrl && !isValidImageUrl(bannerUrl)) return res.json({ success: false, message: 'URL gambar tidak valid' });
    if (bannerUrl && bannerUrl.trim()) {
      p.image    = bannerUrl.trim();
      p.bannerUrl = bannerUrl.trim();
    }

    if (status) p.status = status;
    if (Array.isArray(platforms)) p.platforms = platforms;
    if (typeof description === 'string') p.description = description.slice(0, 2000);
    if (typeof installUrl === 'string') {
      const u = installUrl.trim();
      if (u && !/^https?:\/\//i.test(u)) return res.json({ success: false, message: 'Link cara pasang harus diawali http:// atau https://' });
      p.installUrl = u.slice(0, 500);
    }

    // Kelola harga / pricing options
    const { pricingOptions } = req.body;
    if (Array.isArray(pricingOptions) && pricingOptions.length > 0) {
      const validOpts = normalizePricingOptions(pricingOptions);
      if (validOpts.length > 0) {
        p.pricingOptions = validOpts;
        p.items = validOpts.map(o => ({ l: dur.itemLabel(p.name, o.days, o.unit), p: o.price }));
      }
    }

    // Kelola keys
    if (keys !== undefined && keys !== null) {
      const newKeys = String(keys).split('\n').map(k => k.trim()).filter(k => k);
      if (newKeys.length > 0) {
        p.keys = keysMode === 'replace' ? newKeys : [...(p.keys || []), ...newKeys];
      }
    }

    await writeDB('products.json', products);
    res.json({ success: true, message: 'Produk berhasil diupdate', data: p });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// Admin Upload Banner — di Vercel upload ke Supabase Storage, lokal ke filesystem
app.post('/admin/upload-banner', requireAdmin, multer({ storage: multer.memoryStorage() }).single('banner'), async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'Tidak ada file diupload' });

    if (isVercel) {
      // Vercel: upload ke Supabase Storage
      try {
        const url = await db.uploadImage(req.file.buffer, req.file.originalname, req.file.mimetype);
        return res.json({ success: true, bannerUrl: url });
      } catch (e) {
        return res.json({ success: false, message: e.message });
      }
    }

    // Lokal: simpan di filesystem
    const bannersDir = path.join(__dirname, 'public', 'uploads', 'banners');
    if (!fs.existsSync(bannersDir)) fs.mkdirSync(bannersDir, { recursive: true });
    const filename = `${Date.now()}-${uuidv4()}${safeExt(req.file.originalname)}`;
    fs.writeFileSync(path.join(bannersDir, filename), req.file.buffer);
    res.json({ success: true, bannerUrl: `/uploads/banners/${filename}` });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// Admin Get Theme Settings
app.get('/admin/theme', requireAdmin, async (req, res) => {
  const settings = await readFresh('settings.json');
  res.json({ success: true, data: settings.theme || {} });
});

// Admin Update Theme Settings
app.post('/admin/theme', requireAdmin, async (req, res) => {
  try {
    const { primaryColor, secondaryColor, accentColor, backgroundColor, cardBackground, borderColor, glowColor } = req.body;
    const settings = await readFresh('settings.json');

    const prevTheme = settings.theme || {};
    settings.theme = {
      primaryColor: primaryColor || prevTheme.primaryColor || '#06b6d4',
      secondaryColor: secondaryColor || prevTheme.secondaryColor || '#22d3ee',
      accentColor: accentColor || prevTheme.accentColor || '#67e8f9',
      backgroundColor: backgroundColor || prevTheme.backgroundColor || '#09090b',
      cardBackground: cardBackground || prevTheme.cardBackground || '#111113',
      borderColor: borderColor || prevTheme.borderColor || 'rgba(79,123,255,.15)',
      glowColor: glowColor || prevTheme.glowColor || 'rgba(79,123,255, 0.1)'
    };

    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Tema berhasil diupdate', data: settings.theme });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// ═══════════════════════════════════════════════════════════
// KEY POOL SYSTEM — Format: CODE - X Hari
// ═══════════════════════════════════════════════════════════

// User: halaman aktifkan key
app.get('/activate-key', requireAuth, (req, res) => {
  const user = getSessionUser(req);
  const settings = readDB('settings.json');
  res.render('pages/activate-key', { user, settings, result: null, error: null, code: '' });
});

app.post('/activate-key', requireAuth, async (req, res) => {
  const user = getSessionUser(req);
  const settings = readDB('settings.json');
  const code = (req.body.code || '').trim().toUpperCase();

  // SECURITY: cegah brute-force nebak kode key (sebelumnya tidak ada limit sama sekali)
  const blockCheck = checkActivateKeyBlocked(req.ip);
  if (blockCheck.blocked) {
    return res.render('pages/activate-key', {
      user, settings, result: null, code: '',
      error: `Terlalu banyak percobaan gagal. Coba lagi dalam ${blockCheck.wait} menit.`
    });
  }

  if (!code) return res.render('pages/activate-key', { user, settings, result: null, error: 'Masukkan kode key terlebih dahulu', code: '' });

  // fresh + lock: cegah 1 kode dipakai 2 orang bersamaan (cache basi antar-instance Vercel)
  const lockId = 'activate:' + code;
  if (processingOrders.has(lockId)) {
    return res.render('pages/activate-key', { user, settings, result: null, error: 'Key sedang diproses, coba lagi sebentar.', code });
  }
  processingOrders.add(lockId);
  let key;
  try {
    const keyspool = await readFresh('keyspool.json');
    key = keyspool.find(k => k.code.toUpperCase() === code);

    if (!key) {
      recordActivateKeyFail(req.ip);
      return res.render('pages/activate-key', { user, settings, result: null, error: 'Key tidak ditemukan atau tidak valid', code });
    }
    if (key.used) {
      recordActivateKeyFail(req.ip);
      return res.render('pages/activate-key', { user, settings, result: null, error: 'Key sudah pernah digunakan', code });
    }

    key.used = true;
    key.usedBy = user.id;
    key.usedByUsername = user.username;
    key.usedAt = new Date().toISOString();
    await writeDB('keyspool.json', keyspool);
  } finally {
    processingOrders.delete(lockId);
  }

  res.render('pages/activate-key', {
    user, settings, code,
    result: { code: key.code, duration: key.duration, label: key.label || `${key.duration} Hari`, note: key.note || '' },
    error: null
  });
});

// Admin: lihat semua key pool
app.get('/admin/keyspool', requireAdmin, async (req, res) => {
  res.json({ success: true, data: await readFresh('keyspool.json') });
});

// Admin: tambah key baru
app.post('/admin/keyspool/add', requireAdmin, async (req, res) => {
  try {
    const { code, duration, label, note } = req.body;
    if (!code || !duration) return res.json({ success: false, message: 'Kode dan durasi wajib diisi' });
    const d = parseInt(duration);
    if (isNaN(d) || d <= 0) return res.json({ success: false, message: 'Durasi tidak valid (harus > 0 hari)' });
    const keyspool = await readFresh('keyspool.json');
    if (keyspool.find(k => k.code.toUpperCase() === code.trim().toUpperCase())) {
      return res.json({ success: false, message: 'Kode key sudah ada' });
    }
    keyspool.push({
      id: uuidv4(),
      code: code.trim().toUpperCase(),
      duration: d,
      label: label?.trim() || `${d} Hari`,
      used: false, usedBy: null, usedByUsername: null, usedAt: null,
      note: note?.trim() || '',
      createdAt: new Date().toISOString()
    });
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true, data: keyspool });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Admin: generate key otomatis (bulk)
app.post('/admin/keyspool/generate', requireAdmin, async (req, res) => {
  try {
    const { count, duration, prefix, label } = req.body;
    const n = Math.min(parseInt(count) || 1, 100);
    const d = parseInt(duration);
    if (isNaN(d) || d <= 0) return res.json({ success: false, message: 'Durasi tidak valid' });
    const keyspool = await readFresh('keyspool.json');
    const pref = (prefix || 'KEY').toUpperCase();
    const added = [];
    for (let i = 0; i < n; i++) {
      const code = `${pref}-${crypto.randomBytes(5).toString('hex').toUpperCase()}`; // 40-bit (sebelumnya 24-bit, bisa ditebak)
      keyspool.push({
        id: uuidv4(), code, duration: d,
        label: label?.trim() || `${d} Hari`,
        used: false, usedBy: null, usedByUsername: null, usedAt: null,
        note: '', createdAt: new Date().toISOString()
      });
      added.push(code);
    }
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true, generated: added.length, codes: added, data: keyspool });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Admin: hapus key
app.post('/admin/keyspool/delete/:id', requireAdmin, async (req, res) => {
  try {
    let keyspool = await readFresh('keyspool.json');
    keyspool = keyspool.filter(k => k.id !== req.params.id);
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// VOUCHER SYSTEM
// ═══════════════════════════════════════════════════════════

app.get('/admin/vouchers', requireAdmin, async (req, res) => {
  res.json({ success: true, data: await readFresh('vouchers.json') });
});

app.post('/admin/vouchers/add', requireAdmin, async (req, res) => {
  try {
    const { code, type, value, minPurchase, maxUses, perUserLimit, expiresAt, description } = req.body;
    if (!code || !type || value === undefined) return res.json({ success: false, message: 'Kode, tipe, dan nilai wajib diisi' });
    const val = parseFloat(value);
    if (isNaN(val) || val <= 0) return res.json({ success: false, message: 'Nilai voucher tidak valid' });
    if (type === 'percent' && val > 100) return res.json({ success: false, message: 'Persentase diskon maksimal 100%' });
    const vouchers = await readFresh('vouchers.json');
    if (vouchers.find(v => v.code.toUpperCase() === code.trim().toUpperCase())) {
      return res.json({ success: false, message: 'Kode voucher sudah ada' });
    }
    const newV = {
      id: uuidv4(),
      code: code.trim().toUpperCase(),
      type,
      value: val,
      minPurchase: parseInt(minPurchase) || 0,
      maxUses: parseInt(maxUses) || 0,
      perUserLimit: parseInt(perUserLimit) || 1,
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      description: description?.trim() || '',
      active: true,
      usedCount: 0,
      usages: [],
      createdAt: new Date().toISOString()
    };
    vouchers.push(newV);
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true, data: vouchers });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/vouchers/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const vouchers = await readFresh('vouchers.json');
    const v = vouchers.find(v => v.id === req.params.id);
    if (!v) return res.json({ success: false, message: 'Voucher tidak ditemukan' });
    v.active = !v.active;
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true, active: v.active });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/vouchers/delete/:id', requireAdmin, async (req, res) => {
  try {
    let vouchers = await readFresh('vouchers.json');
    vouchers = vouchers.filter(v => v.id !== req.params.id);
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});
