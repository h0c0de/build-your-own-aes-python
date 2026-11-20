"""Uji Irisan 2 (AES) — ekspansi kunci & AddRoundKey.

Wasit: Apendiks A.1 FIPS-197 secara utuh — ke-44 kata
untuk kunci 2b7e1516..., termasuk nilai antara pada
i=4 (temp, RotWord, SubWord, Rcon) — dan kunci ronde
tiap ronde pada Apendiks C.1 (kunci 000102...).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aes import (add_round_key, ekspansi_kunci, kunci_ronde,
                 rot_word, sub_word)

LULUS = 0


def ok(nama):
    global LULUS
    LULUS += 1
    print("  ok %2d. %s" % (LULUS, nama))


def kata_hex(w):
    return ["".join("%02x" % b for b in kata) for kata in w]


# --- Nilai antara i=4 pada tabel A.1 ---
temp = [0x09, 0xCF, 0x4F, 0x3C]
assert rot_word(temp) == [0xCF, 0x4F, 0x3C, 0x09]
assert sub_word(rot_word(temp)) == [0x8A, 0x84, 0xEB, 0x01]
ok("i=4: RotWord cf4f3c09, SubWord 8a84eb01 (A.1)")

# --- Ke-44 kata Apendiks A.1 ---
KUNCI_A1 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
WA1 = ("2b7e1516 28aed2a6 abf71588 09cf4f3c "
       "a0fafe17 88542cb1 23a33939 2a6c7605 "
       "f2c295f2 7a96b943 5935807a 7359f67f "
       "3d80477d 4716fe3e 1e237e44 6d7a883b "
       "ef44a541 a8525b7f b671253b db0bad00 "
       "d4d1c6f8 7c839d87 caf2b8bc 11f915bc "
       "6d88a37a 110b3efd dbf98641 ca0093fd "
       "4e54f70e 5f5fc9f3 84a64fb2 4ea6dc4f "
       "ead27321 b58dbad2 312bf560 7f8d292f "
       "ac7766f3 19fadc21 28d12941 575c006e "
       "d014f9a8 c9ee2589 e13f0cc8 b6630ca6").split()
w = ekspansi_kunci(KUNCI_A1)
assert kata_hex(w) == WA1
ok("44 kata ekspansi cocok kata-per-kata dengan Apendiks A.1")

# --- Kunci ronde C.1 (kunci 000102...0f) ---
KUNCI_C1 = bytes(range(16))
KSCH_C1 = ["000102030405060708090a0b0c0d0e0f",
           "d6aa74fdd2af72fadaa678f1d6ab76fe",
           "b692cf0b643dbdf1be9bc5006830b3fe",
           "b6ff744ed2c2c9bf6c590cbf0469bf41",
           "47f7f7bc95353e03f96c32bcfd058dfd",
           "3caaa3e8a99f9deb50f3af57adf622aa",
           "5e390f7df7a69296a7553dc10aa31f6b",
           "14f9701ae35fe28c440adf4d4ea9c026",
           "47438735a41c65b9e016baf4aebf7ad2",
           "549932d1f08557681093ed9cbe2c974e",
           "13111d7fe3944a17f307a78b4d2b30c5"]
w2 = ekspansi_kunci(KUNCI_C1)
for ronde in range(11):
    assert bytes(kunci_ronde(w2, ronde)).hex() == KSCH_C1[ronde], ronde
ok("11 kunci ronde cocok dengan k_sch Apendiks C.1")

# --- AddRoundKey: input C.1 xor kunci ronde 0 = start ronde 1 ---
MASUK = bytes.fromhex("00112233445566778899aabbccddeeff")
state = add_round_key(list(MASUK), w2, 0)
assert bytes(state).hex() == "00102030405060708090a0b0c0d0e0f0"
ok("AddRoundKey awal menghasilkan round[1].start C.1")

print("\nIRISAN 2 HIJAU: %d pemeriksaan" % LULUS)
