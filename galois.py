"""GF(2^8) dan S-box AES — diturunkan dari definisi FIPS-197.

Medan beranggotakan 256 byte dengan polinom taktereduksi
m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B). Penjumlahan adalah
XOR; perkalian adalah perkalian polinom modulo m(x)
(FIPS-197 Bagian 4.1-4.2).

S-box TIDAK ditempel dari Tabel 4 standar: ia dibangun
dari definisi 5.1.1 — invers perkalian di GF(2^8)
(dengan {00} dipetakan ke dirinya), diikuti transformasi
afin atas GF(2). Tabel standar hanya menjadi wasit uji.
"""


def xtime(a):
    """Kali dengan x (yaitu {02}) — FIPS-197 4.2.1."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def kali(a, b):
    """Perkalian GF(2^8): jumlah-XOR atas bit-bit b (4.2)."""
    hasil = 0
    while b:
        if b & 1:
            hasil ^= a
        a = xtime(a)
        b >>= 1
    return hasil


def pangkat(a, e):
    hasil = 1
    while e:
        if e & 1:
            hasil = kali(hasil, a)
        a = kali(a, a)
        e >>= 1
    return hasil


def invers(a):
    """Invers perkalian; {00} dipetakan ke {00} (5.1.1)."""
    if a == 0:
        return 0
    return pangkat(a, 254)  # a^254 = a^-1 di GF(2^8)


def _afin(b):
    """Transformasi afin 5.1.1: b xor rotasi-rotasinya xor {63}."""
    s = b
    for geser in (1, 2, 3, 4):
        s ^= ((b << geser) | (b >> (8 - geser))) & 0xFF
    return (s ^ 0x63) & 0xFF


def _bangun_sbox():
    return [_afin(invers(b)) for b in range(256)]


def _bangun_inv_sbox(sbox):
    inv = [0] * 256
    for i, s in enumerate(sbox):
        inv[s] = i
    return inv


SBOX = _bangun_sbox()
INV_SBOX = _bangun_inv_sbox(SBOX)
