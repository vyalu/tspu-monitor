# -*- coding: utf-8 -*-
"""
Проверка HTTP/3 (QUIC) без внешних библиотек.

Отправляем серверу первый пакет QUIC (Initial) с ClientHello и именем сайта (SNI) —
ровно то, что разбирает ТСПУ, — и ждём любого ответа сервера. Ответ пришёл — QUIC
проходит; тишина при живом TCP — QUIC до сервера не доходит (блок по SNI или по UDP).

Шифрование Initial-пакета (RFC 9001, раздел 5) реализовано здесь же: AES-128 и GCM
на чистом Python. Медленно, но нужно один раз на проверку, так что это неважно.
"""
import hashlib
import hmac
import os
import socket
import struct
import time

# ---------------------------------------------------------------- AES-128 (только шифрование)
_SBOX = bytearray(256)
_p = _q = 1
while True:  # построение S-блока через мультипликативную группу GF(2^8)
    _p = _p ^ ((_p << 1) & 0xFF) ^ (0x1B if _p & 0x80 else 0)
    _q ^= _q << 1
    _q ^= _q << 2
    _q ^= _q << 4
    _q &= 0xFF
    if _q & 0x80:
        _q ^= 0x09
    _x = _q ^ ((_q << 1 | _q >> 7) & 0xFF) ^ ((_q << 2 | _q >> 6) & 0xFF) \
        ^ ((_q << 3 | _q >> 5) & 0xFF) ^ ((_q << 4 | _q >> 4) & 0xFF)
    _SBOX[_p] = _x ^ 0x63
    if _p == 1:
        break
_SBOX[0] = 0x63
_SBOX = bytes(_SBOX)


def _xt(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _expand(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xt(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def _enc_block(rk, blk):
    s = [a ^ b for a, b in zip(blk, rk[0])]
    for r in range(1, 11):
        s = [_SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]   # ShiftRows (столбцовый порядок)
        if r != 10:
            m = []
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                m += [a[i] ^ t ^ _xt(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = m
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(s)


class AES:
    def __init__(self, key):
        self.rk = _expand(key)

    def encrypt(self, blk):
        return _enc_block(self.rk, blk)


# ---------------------------------------------------------------- AES-GCM (шифрование)
def _gmul(x, y):
    r, R = 0, 0xE1 << 120
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            r ^= x
        x = (x >> 1) ^ R if x & 1 else x >> 1
    return r


def _ghash(h, aad, ct):
    def blocks(b):
        b = b + b"\x00" * (-len(b) % 16)
        return [int.from_bytes(b[i:i + 16], "big") for i in range(0, len(b), 16)]
    y = 0
    for x in blocks(aad) + blocks(ct) + [(len(aad) * 8) << 64 | len(ct) * 8]:
        y = _gmul(y ^ x, h)
    return y


def gcm_encrypt(key, nonce, plaintext, aad):
    aes = AES(key)
    h = int.from_bytes(aes.encrypt(b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    out = bytearray()
    ctr = 2
    for i in range(0, len(plaintext), 16):
        ks = aes.encrypt(nonce + ctr.to_bytes(4, "big"))
        out += bytes(a ^ b for a, b in zip(plaintext[i:i + 16], ks))
        ctr += 1
    s = _ghash(h, aad, bytes(out))
    tag = (s ^ int.from_bytes(aes.encrypt(j0), "big")).to_bytes(16, "big")
    return bytes(out) + tag


# ---------------------------------------------------------------- ключи Initial (RFC 9001 §5.2)
SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _hkdf_label(secret, label, length):
    full = b"tls13 " + label
    info = struct.pack(">HB", length, len(full)) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def initial_keys(dcid):
    initial = hmac.new(SALT_V1, dcid, hashlib.sha256).digest()
    cs = _hkdf_label(initial, b"client in", 32)
    return _hkdf_label(cs, b"quic key", 16), _hkdf_label(cs, b"quic iv", 12), _hkdf_label(cs, b"quic hp", 16)


# ---------------------------------------------------------------- пакет
def _varint(v):
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return struct.pack(">H", v | 0x4000)
    return struct.pack(">I", v | 0x80000000)


def _ext(typ, body):
    return struct.pack(">HH", typ, len(body)) + body


def client_hello(host, scid):
    name = host.encode("idna")
    tp = b""
    for pid, val in ((0x01, 30000), (0x04, 1048576), (0x05, 262144), (0x06, 262144),
                     (0x07, 262144), (0x08, 100), (0x09, 100)):
        v = _varint(val)
        tp += _varint(pid) + _varint(len(v)) + v
    tp += _varint(0x0F) + _varint(len(scid)) + scid       # initial_source_connection_id
    sni = struct.pack(">BH", 0, len(name)) + name
    exts = (
        _ext(0x0000, struct.pack(">H", len(sni)) + sni)                                   # server_name
        + _ext(0x000A, struct.pack(">HHHH", 6, 0x001D, 0x0017, 0x0018))                   # supported_groups
        + _ext(0x000D, struct.pack(">H8H", 16, 0x0403, 0x0804, 0x0401, 0x0503,
                                   0x0805, 0x0501, 0x0806, 0x0601))                      # signature_algorithms
        + _ext(0x0010, struct.pack(">HB", 3, 2) + b"h3")                                  # ALPN h3
        + _ext(0x002B, b"\x02\x03\x04")                                                   # TLS 1.3
        + _ext(0x002D, b"\x01\x01")                                                       # psk_key_exchange_modes
        + _ext(0x0033, struct.pack(">HHH", 36, 0x001D, 32) + os.urandom(32))             # key_share x25519
        + _ext(0x0039, tp)                                                                # quic_transport_parameters
    )
    body = (b"\x03\x03" + os.urandom(32) + b"\x00"
            + struct.pack(">H3H", 6, 0x1301, 0x1302, 0x1303) + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def initial_packet(host, dcid=None, scid=None, pn=0, crypto=None, size=1200):
    dcid = dcid or os.urandom(8)
    scid = scid or os.urandom(8)
    crypto = crypto if crypto is not None else client_hello(host, scid)
    key, iv, hp = initial_keys(dcid)
    pn_len = 4
    frame = b"\x06" + _varint(0) + _varint(len(crypto)) + crypto
    head_wo_len = (bytes([0xC0 | (pn_len - 1)]) + struct.pack(">I", 1)
                   + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + _varint(0))
    pad = max(0, size - (len(head_wo_len) + 2 + pn_len + len(frame) + 16))
    payload = frame + b"\x00" * pad
    header = head_wo_len + struct.pack(">H", 0x4000 | (pn_len + len(payload) + 16)) + pn.to_bytes(pn_len, "big")
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    ct = gcm_encrypt(key, nonce, payload, header)
    pn_off = len(header) - pn_len
    sample = ct[4 - pn_len:4 - pn_len + 16]
    mask = AES(hp).encrypt(sample)
    h = bytearray(header)
    h[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        h[pn_off + i] ^= mask[1 + i]
    return bytes(h) + ct


def probe(ip, host, port=443, timeout=3.0):
    """True — сервер ответил по QUIC; False — тишина; исключение — сетевая ошибка (нет UDP и т. п.)."""
    pkt = initial_packet(host)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, port))
        deadline = time.monotonic() + timeout
        sends = 0
        while True:
            if sends < 2:                     # один повтор — UDP теряется и без всякой цензуры
                s.send(pkt)
                sends += 1
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            s.settimeout(min(left, timeout / 2))
            try:
                data = s.recv(4096)
            except socket.timeout:
                continue
            except ConnectionRefusedError:    # ICMP «порт закрыт» — сервер QUIC не слушает
                return False
            if data and data[0] & 0x80:       # длинный заголовок: Initial / Retry / Version Negotiation
                return True
    finally:
        s.close()
