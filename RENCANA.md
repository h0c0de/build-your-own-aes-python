# RENCANA — Build 20: AES-128 dari Nol (FIPS-197)

Seri build-your-own-x, build ke-20. Sumber di luar fork:
panduan kali ini adalah standarnya sendiri — **FIPS-197,
Advanced Encryption Standard (AES)**, NIST, 26 Nov 2001.
Seluruh nilai emas di bawah ini dibaca langsung dari
dokumen itu (Apendiks A/B/C) pada 20 Nov 2026, dan
dibuktikan SEBELUM kode proyek ditulis: skrip bukti
sekali-pakai menurunkan S-box murni dari definisi
5.1.1 dan mereproduksi {57}•{83}={c1}, {57}•{13}={fe},
S({00})={63}, S({53})={ed}, dan baris 0 Tabel 4 persis.

## Ruang lingkup (dinyatakan di muka)

- HANYA AES-128: Nk=4, Nb=4, Nr=10. AES-192/256 di luar
  lingkup (pilihan Vero: "AES-128").
- S-box DITURUNKAN dari definisinya (invers perkalian
  di GF(2^8) + transformasi afin), BUKAN ditempel dari
  tabel — tabel standar dipakai hanya sebagai wasit.
- State disimpan sebagai 16 byte urutan kolom-mayor
  persis notasi aliran in[]/out[] standar, supaya jejak
  per ronde bisa dibandingkan string-per-string dengan
  Apendiks C.1.
- Mode operasi (ECB/CBC) ada di irisan 4 sebagai finale
  melawan OpenSSL; mode itu wilayah SP 800-38A, bukan
  FIPS-197 — dilabeli sebagai lanjutan.
- Kode ini untuk BELAJAR. Ia tidak konstan-waktu dan
  tidak terlindung dari serangan kanal-samping; jangan
  dipakai melindungi data sungguhan.

## Irisan

- [x] Irisan 1 — GF(2^8) & S-box: penjumlahan (XOR),
  xtime, perkalian, invers; S-box dari definisi 5.1.1
  dan S-box inversnya. Wasit: contoh-contoh 4.2
  standar, nilai S yang disebut teks 5.1.1, baris 0
  Tabel 4, baris 0 Gambar 14 (S-box invers).
- [x] Irisan 2 — Ekspansi kunci: RotWord, SubWord,
  Rcon, 44 kata untuk AES-128; AddRoundKey. Wasit:
  SELURUH tabel Apendiks A.1 (kunci 2b7e15...) kata
  per kata termasuk nilai antara i=4, dan kunci ronde
  C.1 (kunci 000102...).
- [x] Irisan 3 — Cipher (enkripsi): SubBytes,
  ShiftRows, MixColumns, AddRoundKey, 10 ronde. Wasit:
  jejak lengkap Apendiks C.1 (start/s_box/s_row/m_col/
  k_sch tiap ronde + output 69c4e0d8...) dan contoh
  Apendiks B (output 3925841d...).
- [x] Irisan 4 — Cipher invers (dekripsi) + finale:
  InvShiftRows, InvSubBytes, InvMixColumns; jejak
  dekripsi C.1 (istart/is_row/is_box/ik_add); baterai
  acak pulang-pergi; mode ECB & CBC + bantalan PKCS#7
  dibedakan byte-per-byte melawan OpenSSL 3.0.13.

## Pagar selesai

- [x] `uji_irisan1.py` … `uji_irisan4.py` semua hijau.
- [x] Jejak enkripsi & dekripsi cocok dengan Apendiks
  C.1 untuk SETIAP ronde, bukan hanya keluaran akhir.
- [x] Diferensial OpenSSL: ECB & CBC byte-identik pada
  data acak.
- [x] `CATATAN.md` satu halaman per irisan: konsep inti + temuan.
- [x] Repo GitHub publik `build-your-own-aes-python`
  terbit dan terverifikasi (SHA blob lokal == remote,
  halaman publik terbaca).
