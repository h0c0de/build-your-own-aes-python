"""Uji Irisan 1 (AES) — GF(2^8) dan S-box dari definisi.

Wasitnya adalah dokumen FIPS-197 itu sendiri: contoh
perkalian Bagian 4.2, nilai S-box yang disebut teks
5.1.1, baris pertama Tabel 4 (S-box) dan Gambar 14
(S-box invers). S-box implementasi DITURUNKAN dari
definisi — tabel-tabel di sini hanya wasit.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from galois import INV_SBOX, SBOX, invers, kali, xtime

LULUS = 0


def ok(nama):
    global LULUS
    LULUS += 1
    print("  ok %2d. %s" % (LULUS, nama))


# --- GF(2^8): contoh-contoh Bagian 4.2 standar ---
assert xtime(0x57) == 0xAE
assert kali(0x57, 0x02) == 0xAE
assert kali(0x57, 0x04) == 0x47
assert kali(0x57, 0x08) == 0x8E
assert kali(0x57, 0x10) == 0x07
ok("rantai xtime {57}: {ae} {47} {8e} {07} (4.2.1)")

assert kali(0x57, 0x13) == 0xFE
ok("{57} • {13} = {fe} (contoh penjumlahan parsial 4.2)")

assert kali(0x57, 0x83) == 0xC1
ok("{57} • {83} = {c1} (contoh perkalian penuh 4.2)")

# Sifat medan: komutatif, identitas, invers bekerja.
import random
acak = random.Random(197)
for _ in range(2000):
    a, b = acak.randrange(256), acak.randrange(256)
    assert kali(a, b) == kali(b, a)
    assert kali(a, 1) == a and kali(a, 0) == 0
    if a:
        assert kali(a, invers(a)) == 1
ok("sifat medan pada 2000 pasangan acak (komutatif, invers)")

# --- S-box dari definisi 5.1.1 ---
assert SBOX[0x00] == 0x63 and SBOX[0x53] == 0xED
ok("S({00})={63} dan S({53})={ed} — nilai yang disebut teks 5.1.1")

BARIS0_TABEL4 = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]
assert SBOX[:16] == BARIS0_TABEL4
ok("baris 0 S-box cocok dengan Tabel 4 standar")

BARIS0_GAMBAR14 = [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                   0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]
assert INV_SBOX[:16] == BARIS0_GAMBAR14
ok("baris 0 S-box invers cocok dengan Gambar 14 standar")

assert len(set(SBOX)) == 256
assert all(INV_SBOX[SBOX[b]] == b for b in range(256))
assert all(SBOX[INV_SBOX[b]] == b for b in range(256))
ok("S-box permutasi penuh 256 nilai; inversnya konsisten dua arah")

print("\nIRISAN 1 HIJAU: %d pemeriksaan" % LULUS)
