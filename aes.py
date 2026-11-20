"""AES-128 dari nol — mengikuti FIPS-197 secara harfiah.

State adalah daftar 16 byte dalam urutan kolom-mayor
persis notasi in[]/out[] standar: indeks r + 4*c adalah
baris r, kolom c. Dengan begitu jejak tiap ronde dapat
dibandingkan string-per-string dengan Apendiks C.1.

Kode belajar: tidak konstan-waktu, tidak terlindung
kanal-samping. Jangan pakai untuk data sungguhan.
"""

from galois import INV_SBOX, SBOX, kali, xtime

NB = 4   # kolom state
NK = 4   # kata kunci (AES-128)
NR = 10  # ronde


# ---------- Ekspansi kunci (FIPS-197 5.2) ----------

def rot_word(kata):
    return kata[1:] + kata[:1]


def sub_word(kata):
    return [SBOX[b] for b in kata]


def _rcon(i):
    """Kata Rcon[i]: byte pertama xtime^(i-1)({01}), sisanya 0."""
    c = 1
    for _ in range(i - 1):
        c = xtime(c)
    return [c, 0, 0, 0]


def ekspansi_kunci(kunci):
    """bytes 16 -> daftar 44 kata (tiap kata daftar 4 byte)."""
    if len(kunci) != 16:
        raise ValueError("kunci AES-128 harus 16 byte")
    w = [list(kunci[4 * i:4 * i + 4]) for i in range(NK)]
    for i in range(NK, NB * (NR + 1)):
        temp = list(w[i - 1])
        if i % NK == 0:
            temp = [a ^ b for a, b in
                    zip(sub_word(rot_word(temp)), _rcon(i // NK))]
        w.append([a ^ b for a, b in zip(w[i - NK], temp)])
    return w


def kunci_ronde(w, ronde):
    """16 byte kunci ronde dalam urutan aliran state."""
    return [b for kata in w[NB * ronde:NB * (ronde + 1)] for b in kata]


# ---------- Transformasi state (5.1) ----------

def add_round_key(state, w, ronde):
    kr = kunci_ronde(w, ronde)
    return [s ^ k for s, k in zip(state, kr)]


def sub_bytes(state):
    return [SBOX[b] for b in state]


def shift_rows(state):
    # Baris r bergeser kiri sebanyak r: s'[r][c] = s[r][(c+r) mod 4]
    return [state[r + 4 * ((c + r) % 4)]
            for c in range(4) for r in range(4)]


def _kali_kolom(a, s):
    return (kali(a[0], s[0]) ^ kali(a[1], s[1])
            ^ kali(a[2], s[2]) ^ kali(a[3], s[3]))


def mix_columns(state):
    # Matriks 5.1.3: baris [02 03 01 01] dan rotasinya.
    matriks = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
    keluar = [0] * 16
    for c in range(4):
        kolom = state[4 * c:4 * c + 4]
        for r in range(4):
            keluar[r + 4 * c] = _kali_kolom(matriks[r], kolom)
    return keluar


def enkripsi_blok(blok, w, jejak=None):
    """Enkripsi satu blok 16 byte. Bila `jejak` adalah list,
    pasangan (nama, state) tiap tahap C.1 ditambahkan ke
    dalamnya: start/s_box/s_row/m_col/k_sch per ronde."""
    if len(blok) != 16:
        raise ValueError("blok harus 16 byte")
    state = add_round_key(list(blok), w, 0)
    if jejak is not None:
        jejak.append(("k_sch0", kunci_ronde(w, 0)))
    for ronde in range(1, NR):
        if jejak is not None:
            jejak.append(("start", state))
        state = sub_bytes(state)
        if jejak is not None:
            jejak.append(("s_box", state))
        state = shift_rows(state)
        if jejak is not None:
            jejak.append(("s_row", state))
        state = mix_columns(state)
        if jejak is not None:
            jejak.append(("m_col", state))
            jejak.append(("k_sch", kunci_ronde(w, ronde)))
        state = add_round_key(state, w, ronde)
    if jejak is not None:
        jejak.append(("start", state))
    state = sub_bytes(state)
    if jejak is not None:
        jejak.append(("s_box", state))
    state = shift_rows(state)
    if jejak is not None:
        jejak.append(("s_row", state))
        jejak.append(("k_sch", kunci_ronde(w, NR)))
    state = add_round_key(state, w, NR)
    return bytes(state)


# ---------- Transformasi invers (5.3) ----------

def inv_shift_rows(state):
    # Kebalikan shift_rows: s'[r][c] = s[r][(c-r) mod 4]
    return [state[r + 4 * ((c - r) % 4)]
            for c in range(4) for r in range(4)]


def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def inv_mix_columns(state):
    # Matriks 5.3.3: baris [0e 0b 0d 09] dan rotasinya.
    matriks = ((0x0E, 0x0B, 0x0D, 0x09), (0x09, 0x0E, 0x0B, 0x0D),
               (0x0D, 0x09, 0x0E, 0x0B), (0x0B, 0x0D, 0x09, 0x0E))
    keluar = [0] * 16
    for c in range(4):
        kolom = state[4 * c:4 * c + 4]
        for r in range(4):
            keluar[r + 4 * c] = _kali_kolom(matriks[r], kolom)
    return keluar


def dekripsi_blok(blok, w, jejak=None):
    """Dekripsi satu blok 16 byte (Cipher Invers 5.3,
    urutan Fig. 12 standar). Jejak memakai nama C.1:
    istart/is_row/is_box/ik_sch/ik_add per ronde."""
    if len(blok) != 16:
        raise ValueError("blok harus 16 byte")
    state = add_round_key(list(blok), w, NR)
    if jejak is not None:
        jejak.append(("ik_sch0", kunci_ronde(w, NR)))
    for ronde in range(NR - 1, 0, -1):
        if jejak is not None:
            jejak.append(("istart", state))
        state = inv_shift_rows(state)
        if jejak is not None:
            jejak.append(("is_row", state))
        state = inv_sub_bytes(state)
        if jejak is not None:
            jejak.append(("is_box", state))
            jejak.append(("ik_sch", kunci_ronde(w, ronde)))
        state = add_round_key(state, w, ronde)
        if jejak is not None:
            jejak.append(("ik_add", state))
        state = inv_mix_columns(state)
    if jejak is not None:
        jejak.append(("istart", state))
    state = inv_shift_rows(state)
    if jejak is not None:
        jejak.append(("is_row", state))
    state = inv_sub_bytes(state)
    if jejak is not None:
        jejak.append(("is_box", state))
        jejak.append(("ik_sch", kunci_ronde(w, 0)))
    state = add_round_key(state, w, 0)
    return bytes(state)


# ---------- Mode operasi (lanjutan SP 800-38A) ----------

def _pkcs7_isikan(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _pkcs7_lepas(data):
    if not data or len(data) % 16:
        raise ValueError("panjang tidak valid untuk bantalan PKCS#7")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bantalan PKCS#7 rusak")
    return data[:-n]


def ecb_enkripsi(data, w):
    data = _pkcs7_isikan(bytes(data))
    return b"".join(enkripsi_blok(data[i:i + 16], w)
                    for i in range(0, len(data), 16))


def ecb_dekripsi(data, w):
    if not data or len(data) % 16:
        raise ValueError("ciphertext ECB harus kelipatan 16 byte")
    polos = b"".join(dekripsi_blok(data[i:i + 16], w)
                     for i in range(0, len(data), 16))
    return _pkcs7_lepas(polos)


def cbc_enkripsi(data, w, iv):
    if len(iv) != 16:
        raise ValueError("IV CBC harus 16 byte")
    data = _pkcs7_isikan(bytes(data))
    keluar, rantai = [], bytes(iv)
    for i in range(0, len(data), 16):
        blok = bytes(a ^ b for a, b in zip(data[i:i + 16], rantai))
        rantai = enkripsi_blok(blok, w)
        keluar.append(rantai)
    return b"".join(keluar)


def cbc_dekripsi(data, w, iv):
    if len(iv) != 16:
        raise ValueError("IV CBC harus 16 byte")
    if not data or len(data) % 16:
        raise ValueError("ciphertext CBC harus kelipatan 16 byte")
    keluar, rantai = [], bytes(iv)
    for i in range(0, len(data), 16):
        blok = data[i:i + 16]
        polos = dekripsi_blok(blok, w)
        keluar.append(bytes(a ^ b for a, b in zip(polos, rantai)))
        rantai = blok
    return _pkcs7_lepas(b"".join(keluar))
