"""Uji Irisan 3 (AES) — Cipher enkripsi, jejak penuh.

Wasit terkuat seri ini: Apendiks C.1 FIPS-197 mencetak
state pada SETIAP tahap tiap ronde (start, s_box,
s_row, m_col, k_sch). Jejak implementasi harus cocok
pada seluruh 51 nilai, bukan hanya keluaran akhir.
Ditambah contoh Apendiks B sebagai vektor kedua.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aes import ekspansi_kunci, enkripsi_blok

LULUS = 0


def ok(nama):
    global LULUS
    LULUS += 1
    print("  ok %2d. %s" % (LULUS, nama))


# Jejak C.1: per ronde (start, s_box, s_row, m_col, k_sch);
# ronde 10 tanpa m_col. k_sch ronde 0 dicek terpisah.
JEJAK_C1 = [
    ("00102030405060708090a0b0c0d0e0f0", "63cab7040953d051cd60e0e7ba70e18c",
     "6353e08c0960e104cd70b751bacad0e7", "5f72641557f5bc92f7be3b291db9f91a",
     "d6aa74fdd2af72fadaa678f1d6ab76fe"),
    ("89d810e8855ace682d1843d8cb128fe4", "a761ca9b97be8b45d8ad1a611fc97369",
     "a7be1a6997ad739bd8c9ca451f618b61", "ff87968431d86a51645151fa773ad009",
     "b692cf0b643dbdf1be9bc5006830b3fe"),
    ("4915598f55e5d7a0daca94fa1f0a63f7", "3b59cb73fcd90ee05774222dc067fb68",
     "3bd92268fc74fb735767cbe0c0590e2d", "4c9c1e66f771f0762c3f868e534df256",
     "b6ff744ed2c2c9bf6c590cbf0469bf41"),
    ("fa636a2825b339c940668a3157244d17", "2dfb02343f6d12dd09337ec75b36e3f0",
     "2d6d7ef03f33e334093602dd5bfb12c7", "6385b79ffc538df997be478e7547d691",
     "47f7f7bc95353e03f96c32bcfd058dfd"),
    ("247240236966b3fa6ed2753288425b6c", "36400926f9336d2d9fb59d23c42c3950",
     "36339d50f9b539269f2c092dc4406d23", "f4bcd45432e554d075f1d6c51dd03b3c",
     "3caaa3e8a99f9deb50f3af57adf622aa"),
    ("c81677bc9b7ac93b25027992b0261996", "e847f56514dadde23f77b64fe7f7d490",
     "e8dab6901477d4653ff7f5e2e747dd4f", "9816ee7400f87f556b2c049c8e5ad036",
     "5e390f7df7a69296a7553dc10aa31f6b"),
    ("c62fe109f75eedc3cc79395d84f9cf5d", "b415f8016858552e4bb6124c5f998a4c",
     "b458124c68b68a014b99f82e5f15554c", "c57e1c159a9bd286f05f4be098c63439",
     "14f9701ae35fe28c440adf4d4ea9c026"),
    ("d1876c0f79c4300ab45594add66ff41f", "3e175076b61c04678dfc2295f6a8bfc0",
     "3e1c22c0b6fcbf768da85067f6170495", "baa03de7a1f9b56ed5512cba5f414d23",
     "47438735a41c65b9e016baf4aebf7ad2"),
    ("fde3bad205e5d0d73547964ef1fe37f1", "5411f4b56bd9700e96a0902fa1bb9aa1",
     "54d990a16ba09ab596bbf40ea111702f", "e9f74eec023020f61bf2ccf2353c21c7",
     "549932d1f08557681093ed9cbe2c974e"),
    ("bd6e7c3df2b5779e0b61216e8b10b689", "7a9f102789d5f50b2beffd9f3dca4ea7",
     "7ad5fda789ef4e272bca100b3d9ff59f", None,
     "13111d7fe3944a17f307a78b4d2b30c5"),
]

KUNCI = bytes(range(16))
POLOS = bytes.fromhex("00112233445566778899aabbccddeeff")
w = ekspansi_kunci(KUNCI)
jejak = []
sandi = enkripsi_blok(POLOS, w, jejak)

assert sandi.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
ok("keluaran C.1: 69c4e0d86a7b0430d8cdb78070b4c55a")

# Ratakan jejak implementasi menjadi urutan (nama, hex).
alur = [(nama, bytes(s).hex()) for nama, s in jejak]
assert alur[0] == ("k_sch0", "000102030405060708090a0b0c0d0e0f")
alur = alur[1:]
# Ratakan harapan C.1 dengan nama yang sama.
harap = []
for start, s_box, s_row, m_col, k_sch in JEJAK_C1:
    harap.append(("start", start))
    harap.append(("s_box", s_box))
    harap.append(("s_row", s_row))
    if m_col is not None:
        harap.append(("m_col", m_col))
    harap.append(("k_sch", k_sch))
assert alur == harap, [x for x in zip(alur, harap) if x[0] != x[1]][:2]
ok("jejak 50 nilai (10 ronde x start/s_box/s_row/m_col/k_sch) "
   "cocok penuh dengan C.1")

# Contoh Apendiks B: kunci & masukan berbeda.
w_b = ekspansi_kunci(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
sandi_b = enkripsi_blok(bytes.fromhex("3243f6a8885a308d313198a2e0370734"),
                        w_b)
assert sandi_b.hex() == "3925841d02dc09fbdc118597196a0b32"
ok("contoh Apendiks B: keluaran 3925841d02dc09fbdc118597196a0b32")

print("\nIRISAN 3 HIJAU: %d pemeriksaan" % LULUS)
