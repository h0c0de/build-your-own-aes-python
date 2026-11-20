# CATATAN — AES-128 dari Nol (FIPS-197)

Panduan build ini adalah standarnya sendiri: FIPS-197
(NIST, 2001). Tidak ada tutorial perantara — yang
dibaca adalah spesifikasi, dan wasitnya adalah contoh
tercetak di apendiks dokumen yang sama, ditambah
OpenSSL sebagai wasit kedua yang independen.

## Irisan 1 — Semua AES adalah aritmetika GF(2^8)

Byte adalah polinom derajat < 8; penjumlahannya XOR,
perkaliannya perkalian polinom modulo
m(x) = x^8+x^4+x^3+x+1. Perkalian dengan x ("xtime")
cukup geser-kiri + XOR 0x11B bila bit ke-8 menyala —
dari operasi sekecil itu seluruh medan terbangun:
perkalian umum adalah jumlah-XOR atas bit pengali
(contoh standar {57}•{83}={c1} direproduksi persis),
dan invers adalah pangkat 254.

S-box SENGAJA diturunkan, bukan ditempel: invers
perkalian (dengan {00}->dirinya) diikuti transformasi
afin b ^ rot1 ^ rot2 ^ rot3 ^ rot4 ^ {63}. Turunan itu
mereproduksi baris 0 Tabel 4 standar persis — bukti
bahwa definisi 5.1.1 dan tabelnya adalah objek yang
sama, dan bahwa salinan tabel dari internet tidak
pernah diperlukan.

## Irisan 2 — Ekspansi kunci adalah separuh algoritma

44 kata untuk AES-128: tiap kata keempat melewati
RotWord -> SubWord -> XOR Rcon sebelum di-XOR dengan
kata 4 posisi sebelumnya. Apendiks A.1 mencetak tabel
ini lengkap dengan nilai antara (pada i=4: temp
09cf4f3c menjadi a0fafe17 lewat empat langkah yang
semuanya bisa dicek sendiri) — ke-44 kata implementasi
ini cocok kata-per-kata. Rcon di sini tidak ditulis
sebagai konstanta hafalan: ia dibangkitkan dengan
xtime berulang dari {01}, jadi irisan 1 yang
membuktikan irisan 2.

## Irisan 3 — Jejak C.1: wasit terkuat seri ini

Apendiks C.1 tidak hanya memberi vektor uji akhir —
ia mencetak state pada SETIAP tahap SETIAP ronde:
start, sesudah SubBytes, sesudah ShiftRows, sesudah
MixColumns, dan kunci ronde, untuk 10 ronde. Dengan
menyimpan state sebagai 16 byte urutan kolom-mayor
persis notasi in[] standar, jejak implementasi bisa
dibandingkan string-per-string: 50 nilai, semuanya
cocok, ditambah vektor kedua Apendiks B
(3925841d...). Artinya bukan cuma "keluarannya benar"
— seluruh lintasan internalnya terbukti identik
dengan contoh resmi standar.

Dua keputusan kecil yang menentukan: ShiftRows
dirumuskan s'[r][c] = s[r][(c+r) mod 4] langsung pada
indeks aliran (tanpa matriks 2D), dan MixColumns
memakai matriks standar apa adanya dengan perkalian
GF dari irisan 1 — tidak ada tabel perkalian
pra-hitung, supaya rantai buktinya tidak putus.

## Irisan 4 — Invers yang simetris, dan wasit kedua

Cipher invers (urutan Fig. 12 standar) memiliki
jejak resmi C.1-nya sendiri — 49 nilai istart/is_row/
is_box/ik_add — dan semuanya cocok juga, termasuk
pengamatan elegan dari standar: ik_add ronde invers
ke-r persis sama dengan m_col ronde enkripsi
pasangannya. AddRoundKey adalah inversnya sendiri
karena ia hanya XOR.

Finale keluar dari dokumen: mode ECB & CBC (wilayah
SP 800-38A, dilabeli lanjutan) dengan bantalan PKCS#7
dibedakan melawan OpenSSL 3.0.13 — 30 data acak per
mode, byte-identik dua arah (OpenSSL mendekripsi
keluaran implementasi ini dan sebaliknya). Ditambah
200 blok acak pulang-pergi dan penolakan masukan
rusak. Peringatan yang tidak boleh hilang: kode ini
murni untuk belajar — tidak konstan-waktu, tidak
tahan kanal-samping; untuk data sungguhan pakailah
pustaka yang teraudit.
