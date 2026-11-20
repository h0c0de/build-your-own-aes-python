# Build Your Own AES — AES-128 dari Nol (FIPS-197)

Implementasi ulang **AES-128** langsung dari dokumen
standarnya, **FIPS-197** (NIST): GF(2^8), S-box yang
*diturunkan* dari definisinya (bukan ditempel dari
tabel), ekspansi kunci, cipher 10 ronde, cipher
invers, plus mode ECB/CBC.

Verifikasinya memakai contoh tercetak standar itu
sendiri: jejak enkripsi cocok dengan Apendiks C.1 pada
**50 nilai antara**, jejak dekripsi pada **49 nilai**,
ekspansi kunci pada **44 kata** Apendiks A.1 — dan
mode-modanya byte-identik dengan OpenSSL.

> Kode belajar: tidak konstan-waktu dan tidak tahan
> serangan kanal-samping. Jangan pakai untuk
> melindungi data sungguhan.

## Isi

- `galois.py` — aritmetika GF(2^8) (xtime, perkalian,
  invers) dan pembangunan S-box + S-box invers dari
  definisi FIPS-197 5.1.1.
- `aes.py` — ekspansi kunci, transformasi state,
  `enkripsi_blok` / `dekripsi_blok` (dengan jejak
  opsional berformat Apendiks C.1), dan mode ECB/CBC
  berlapis PKCS#7.
- `uji_irisan1.py` … `uji_irisan4.py` — baterai uji
  per irisan (total 21 pemeriksaan): contoh Bagian
  4.2 standar, Tabel 4 & Gambar 14, Apendiks A.1,
  jejak penuh Apendiks C.1 dua arah, Apendiks B, 200
  blok acak pulang-pergi, diferensial OpenSSL.

## Menjalankan

```bash
python3 uji_irisan1.py   # dst. sampai uji_irisan4.py
```

Hanya pustaka standar. Uji irisan 4 juga memanggil
`openssl` dari PATH sebagai wasit diferensial.

## Atribusi

Algoritma dan seluruh nilai uji berasal dari
*FIPS Publication 197, Advanced Encryption Standard
(AES)*, National Institute of Standards and
Technology, 26 November 2001 — dokumen pemerintah AS,
diimplementasikan ulang sebagai latihan belajar.
