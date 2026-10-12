-- ============================================================
-- Luxzco — RPC hemat egress (jalankan SEKALI di Supabase → SQL Editor)
-- Aman dijalankan ulang. Tanpa ini aplikasi tetap jalan (jatuh ke mode lama yang boros egress).
--
-- Kenapa: transaksi disimpan sebagai 1 array JSON besar (key 'transactions.json'). Tanpa fungsi ini,
-- setiap poll status pembayaran / cek pesanan / buka dashboard menarik SELURUH array itu dari Supabase.
-- Dengan fungsi ini, database yang mencari dan hanya 1 transaksi (atau transaksi 1 user) yang dikirim.
-- ============================================================

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
