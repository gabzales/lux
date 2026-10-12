-- Luxzco — Supabase Schema
-- Jalankan ini di: Supabase Dashboard → SQL Editor → New Query → Run

-- 1. Buat tabel
CREATE TABLE IF NOT EXISTS keyvalue_store (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Auto-update updated_at
CREATE OR REPLACE FUNCTION _set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_set_updated_at ON keyvalue_store;
CREATE TRIGGER trg_set_updated_at
  BEFORE UPDATE ON keyvalue_store
  FOR EACH ROW EXECUTE FUNCTION _set_updated_at();

-- 3. Seed semua collections agar tidak null
INSERT INTO keyvalue_store (key, value) VALUES
  ('products.json',     '[]'::jsonb),
  ('users.json',        '[]'::jsonb),
  ('transactions.json', '[]'::jsonb),
  ('testimonials.json', '[]'::jsonb),
  ('notifications.json','[]'::jsonb),
  ('keyspool.json',     '[]'::jsonb),
  ('vouchers.json',     '[]'::jsonb),
  ('settings.json',     '{}'::jsonb),
  ('admin-lock.json',   '{}'::jsonb)
ON CONFLICT (key) DO NOTHING;

-- 4. Row Level Security — HANYA service_role yang boleh akses penuh.
-- Service role key otomatis BYPASS RLS, jadi policy di bawah ini
-- sebenarnya untuk mengunci akses anon/public sepenuhnya.
ALTER TABLE keyvalue_store ENABLE ROW LEVEL SECURITY;

-- Hapus policy lama yang mengizinkan SEMUA orang (anon key) baca/tulis bebas.
DROP POLICY IF EXISTS "allow_all" ON keyvalue_store;

-- Cabut semua privilege dari role anon & authenticated di tabel ini.
-- Server kita TIDAK BOLEH pakai anon key untuk tabel ini lagi —
-- gunakan SUPABASE_SERVICE_ROLE_KEY di server (lihat supabase.js).
REVOKE ALL ON keyvalue_store FROM anon;
REVOKE ALL ON keyvalue_store FROM authenticated;

-- Tidak perlu CREATE POLICY untuk service_role — service_role key
-- selalu bypass RLS secara default di Supabase/Postgres.

-- ============================================================
-- SUPABASE STORAGE — untuk upload gambar produk
-- ============================================================

-- 5. Buat bucket untuk gambar produk (public)
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'product-images',
  'product-images',
  true,
  5242880, -- 5MB
  ARRAY['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp']::text[]
)
ON CONFLICT (id) DO NOTHING;

-- 6. Policy: publik boleh LIHAT gambar produk (read-only, ini memang harus public)
DROP POLICY IF EXISTS "allow_public_select" ON storage.objects;
CREATE POLICY "allow_public_select" ON storage.objects
  FOR SELECT USING (bucket_id = 'product-images');

-- Upload gambar HANYA lewat server (service_role), bukan langsung dari anon/browser.
-- Service role bypass RLS, jadi policy insert untuk anon kita hapus saja.
DROP POLICY IF EXISTS "allow_public_insert" ON storage.objects;

-- 7. RPC hemat egress (lihat migrations/2026-10-07-egress-rpc.sql)

CREATE OR REPLACE FUNCTION get_transaction_by(p_field text, p_value text)
RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT elem
  FROM (SELECT value FROM keyvalue_store WHERE key = 'transactions.json' AND jsonb_typeof(value) = 'array') s,
       LATERAL jsonb_array_elements(s.value) AS elem
  WHERE p_field IN ('id', 'code') AND elem ->> p_field = p_value
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION get_user_transactions(p_user text)
RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
  FROM (SELECT value FROM keyvalue_store WHERE key = 'transactions.json' AND jsonb_typeof(value) = 'array') s,
       LATERAL jsonb_array_elements(s.value) AS elem
  WHERE elem ->> 'userId' = p_user;
$$;

-- Hanya service_role (server) yang boleh memanggil. anon/authenticated DICABUT: fungsi ini membaca data transaksi + key.
REVOKE ALL ON FUNCTION get_transaction_by(text, text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION get_user_transactions(text)    FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION get_transaction_by(text, text) TO service_role;
GRANT EXECUTE ON FUNCTION get_user_transactions(text)    TO service_role;

-- Verifikasi
SELECT key, updated_at FROM keyvalue_store ORDER BY key;
