# Luxzco (vipluxzco)

Toko key lisensi & produk digital. Node.js + Express + EJS, database Supabase (tabel `keyvalue_store`), deploy ke Vercel.

## Cara kerja saat ini
- **Pembayaran manual**: pembeli scan QRIS statis, admin mengonfirmasi lewat admin panel (Transaksi → Konfirmasi). Integrasi PakKasir tetap ada di kode tapi tidak dipakai selama `qrisMode = static`.
- **Stok key manual**: admin menambah key per produk/durasi dari admin panel. Tidak ada auto restock.

## Setup lokal
```bash
npm install
cp .env.example .env     # isi SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_SECRET
# jalankan supabase-schema.sql di Supabase SQL Editor (project BARU untuk Luxzco)
SEED_ADMIN_USERNAME=admin SEED_ADMIN_PASSWORD=ganti-ini node seed-settings.js
npm start
```
Buka `http://localhost:3000`. Login admin di `/lx-secure-panel-7k`.

## Lupa / salah password admin
Login admin dicek terhadap hash di **Supabase** (`settings.json`), bukan env. Env `INITIAL_ADMIN_*` hanya dipakai sekali saat settings masih kosong. Reset yang pasti (langsung berlaku, tanpa redeploy):
```bash
node reset-admin.js admin "password-baru-min-8-karakter"
```
Pastikan `SUPABASE_URL` di `.env` lokal = project yang dipakai Vercel (script menampilkan project ref). Cek log server bila gagal: baris `[admin-login] GAGAL ...` menyebut bagian mana yang salah (username/password) tanpa membocorkan nilainya.

## Keamanan & hemat kuota gratis
- `.env` dan `database/` (backup lokal berisi semua key + hash admin) sudah di `.gitignore`. Jangan di-commit.
- Isi key produk **tidak pernah** dikirim ke halaman publik/API publik; hanya jumlah stok. Key hanya tampil ke pemilik transaksi (dashboard / check-payment) atau pemegang kode order (Cek Pesanan).
- API publik (`/api/notifications`, `/api/banners`, `/api/products`, ...) di-cache CDN Vercel 30–60 detik; polling notifikasi 60 detik dan berhenti saat tab tidak terlihat.
- Jangan upload banner sebagai base64 ke settings — upload ke Supabase Storage (bucket `product-images`).

## Update 2026-10-07 — keamanan & hemat egress (WAJIB baca)
1. **Jalankan SQL sekali** di Supabase → SQL Editor: `migrations/2026-10-07-egress-rpc.sql`.
   Tanpa ini aplikasi tetap jalan, tapi polling pembayaran / cek pesanan / dashboard masih menarik SELURUH
   `transactions.json` dari Supabase di setiap request (log server akan menulis peringatan `[supabase] RPC ... belum dibuat`).
2. **Isi `TURNSTILE_SITE_KEY` + `TURNSTILE_SECRET_KEY`** di env Vercel. Rate limit login berbasis memori TIDAK dibagi antar-instance
   serverless, jadi captcha-lah yang benar-benar menahan brute-force. Sekarang aktif juga di login admin.
3. Pastikan `SESSION_SECRET` terisi di env Vercel (kalau kosong, tiap instance membuat secret acak → sesi login saling tidak valid).
4. Ringkasan temuan & perubahan: `AUDIT-2026-10-07.md`.

## Setelah deploy pertama
1. Admin panel → Pengaturan: isi nomor WhatsApp, saluran WA, TikTok (footer menyembunyikan yang kosong).
2. Upload gambar QRIS statis.
3. Tambah produk, durasi/harga, dan key.

## Logo & banner
- Logo = wordmark teks `public/uploads/logo-luxzco-text.png` (dipakai di semua halaman, favicon `favicon-lx.png`, OG `og-luxzco.jpg`). URL logo lama di database otomatis diganti ke wordmark ini.
- Banner home: upload dari Admin → Banner. Gambar sebaiknya 1600x500 (rasio 16:5) dengan teks sudah ada di gambar; kolom judul/subjudul dikosongkan supaya tidak tumpang tindih.
- Untuk memakai banner bawaan lagi di database yang sudah ada: `SEED_RESET_BANNERS=1 node seed-settings.js`.
- Teks berjalan di bawah banner: Admin → Pengaturan → pisahkan kalimat dengan `|`.

## Halaman detail produk
- Admin → Produk → Edit: isi **Deskripsi** (satu fitur per baris, boleh emoji) dan **Link Cara Pasang / Download**. Kalau link diisi, tombol "Cara Pasang / Download" muncul di halaman produk.
- Durasi yang stoknya habis otomatis redup dan tidak bisa dipilih. Durasi pertama yang masih ada stok terpilih secara default.
- Pembeli mengisi nama (bebas) dan nomor WhatsApp. Email tidak lagi diminta.

## Testimoni (Admin → Testimoni)
- **Real (pembeli)**: ulasan dari pembeli yang transaksinya sudah selesai. Ikut dihitung ke rating bintang di kartu produk.
- **Manual (admin)**: ditambahkan admin lewat tombol "Tambah manual". Tampil di bagian "Kata Mereka" saja dan tidak ikut rating produk. Isi hanya dengan testimoni dari pelanggan nyata.
- Setiap testimoni bisa ditampilkan/disembunyikan, di-pin ke urutan depan, atau dihapus.

## Kontak (Admin → Pengaturan)
WhatsApp admin, Telegram (username), Saluran WhatsApp (kode setelah `/channel/`), TikTok, Email. Yang kosong otomatis tidak tampil di footer, tombol chat, dan halaman produk.

## Install aplikasi
Situs punya manifest + service worker minimal. Tombol "Install Aplikasi" di footer muncul otomatis di browser yang mendukung (Android/Chrome) dan menampilkan petunjuk di iOS Safari.

## Tema
Deep blue + hitam. Token warna ada di `views/layout.ejs` (`:root`). Font: Chakra Petch (judul), Plus Jakarta Sans (isi).

## Pembayaran GensPay (QRIS otomatis)
1. Isi di Vercel → Settings → Environment Variables: `GENSPAY_API_KEY`, `APP_URL` (mis. `https://toko-kamu.vercel.app`), opsional `GENSPAY_BASE_URL`. Redeploy.
2. Admin → Pengaturan → Pengaturan QRIS → pilih **GensPay** → klik *Test Koneksi GensPay*.
3. Alur: checkout membuat QRIS di GensPay → pembeli bayar → GensPay memanggil `POST /webhook/genspay` (signature `SHA256(rawBody + API_KEY)` diverifikasi) → key otomatis dikirim. Halaman pembeli hanya membaca database (tidak memanggil GensPay), jadi hemat kuota Vercel/Supabase.
4. Bila GensPay error saat membuat QR dan gambar QRIS statis tersedia, checkout otomatis jatuh ke QRIS statis (konfirmasi manual).

## Auto-restock (Drip Store / Ghostseller)
1. Isi `DRIPSTORE_API_TOKEN` (dan/atau `GHOSTSELLER_API_KEY`) di environment Vercel, Redeploy. Cek di Admin → Pengaturan → *Auto-Restock Provider* → tombol Tes.
2. Admin → Produk → Edit → kartu **Auto-Restock**: pilih provider, pilih produknya, petakan tiap paket (hari/jam) ke varian. Kosong = stok lokal saja.
3. Saat pembayaran lunas: stok lokal dipakai dulu; kalau habis, key diambil dari provider.
   - **Ghostseller**: `idempotencyKey` = kode order → retry tidak pernah menerbitkan 2 key.
   - **Drip Store** (tidak punya idempotency): percobaan dicatat ke DB *sebelum* memanggil provider. Timeout/koneksi putus/5xx = "saldo mungkin terpotong" → **tidak** diulang otomatis, pesanan ditandai manual + WA ke admin (cek Riwayat di dashboard Drip Store dulu). Hanya kegagalan yang pasti belum diproses (429, saldo/stok habis, 401/403) yang boleh dicoba lagi.
   - Error sementara (429) → pesanan tetap pending dan dicoba lagi otomatis. Saldo/stok habis/akses ditolak → ditandai manual + paket itu "libur" 10 menit agar tak ada yang bayar untuk stok yang tak ada.
4. Varian Drip Store Bala Mod mode `v1` (butuh Android ID pembeli) ditandai *tidak didukung* dan tidak bisa dipetakan; mode `both` memakai `v2` (key langsung).

## Varian jam
Di form harga produk, tiap paket punya satuan **Hari** atau **Jam**. Tag key per durasi: `KEY:7` (7 hari), `KEY:3h` (3 jam); tanpa tag = bisa untuk durasi apa pun.

