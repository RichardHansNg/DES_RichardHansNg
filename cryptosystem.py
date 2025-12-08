import random
from typing import Tuple, List

def _right_rotate(x: int, r: int) -> int:
    return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF

_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

_H0 = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
]

def sha256_bytes(data: bytes) -> bytes:
    ml = len(data) * 8
    data += b'\x80'
    while ((len(data) * 8) + 64) % 512 != 0:
        data += b'\x00'
    data += ml.to_bytes(8, 'big')

    H = _H0.copy()

    for chunk_start in range(0, len(data), 64):
        chunk = data[chunk_start:chunk_start + 64]
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*4:(i+1)*4], 'big')
        for i in range(16, 64):
            s0 = (_right_rotate(w[i-15], 7) ^ _right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)) & 0xFFFFFFFF
            s1 = (_right_rotate(w[i-2], 17) ^ _right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)) & 0xFFFFFFFF
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

        a,b,c,d,e,f,g,h = H
        for i in range(64):
            S1 = (_right_rotate(e,6) ^ _right_rotate(e,11) ^ _right_rotate(e,25)) & 0xFFFFFFFF
            ch = ((e & f) ^ ((~e) & g)) & 0xFFFFFFFF
            temp1 = (h + S1 + ch + _K[i] + w[i]) & 0xFFFFFFFF
            S0 = (_right_rotate(a,2) ^ _right_rotate(a,13) ^ _right_rotate(a,22)) & 0xFFFFFFFF
            maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        H = [
            (H[0] + a) & 0xFFFFFFFF,
            (H[1] + b) & 0xFFFFFFFF,
            (H[2] + c) & 0xFFFFFFFF,
            (H[3] + d) & 0xFFFFFFFF,
            (H[4] + e) & 0xFFFFFFFF,
            (H[5] + f) & 0xFFFFFFFF,
            (H[6] + g) & 0xFFFFFFFF,
            (H[7] + h) & 0xFFFFFFFF,
        ]

    digest = b''.join(hv.to_bytes(4, 'big') for hv in H)
    return digest

def sha256_hex(data: bytes) -> str:
    return sha256_bytes(data).hex()

# ----------------------------
# RSA Utilities
# ----------------------------
def egcd(a: int, b: int) -> Tuple[int,int,int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

def is_probable_prime(n: int, k: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p

    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits: int) -> int:
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p

def gen_rsa_keypair(bits: int = 2048) -> Tuple[int,int,int]:
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    while q == p:
        q = gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if phi % e == 0:
        e = 3
        while egcd(e, phi)[0] != 1:
            e += 2
    d = modinv(e, phi)
    return (n, e, d)

def rsa_encrypt_int(m_int: int, e: int, n: int) -> int:
    return pow(m_int, e, n)

def rsa_decrypt_int(c_int: int, d: int, n: int) -> int:
    return pow(c_int, d, n)

# ----------------------------
# Signing / Verification
# ----------------------------
def sign_bytes_with_rsa(d: int, n: int, data: bytes) -> str:
    """
    Hash data with SHA-256, interpret hash as integer, sign with RSA private key.
    Returns uppercase hex string without '0x' prefix.
    """
    h_hex = sha256_hex(data)
    h_int = int(h_hex, 16)
    sig_int = rsa_decrypt_int(h_int, d, n)
    return hex(sig_int)[2:].upper()

def verify_bytes_with_rsa(e: int, n: int, data: bytes, sig_hex: str) -> bool:
    """
    Verify numeric signature created by sign_bytes_with_rsa.
    """
    try:
        sig_int = int(sig_hex, 16)
    except Exception:
        return False
    h_hex = sha256_hex(data)
    h_int = int(h_hex, 16)
    verification = rsa_encrypt_int(sig_int, e, n)
    return verification == (h_int % n)

# ----------------------------
# Small helpers
# ----------------------------
def int_to_hex_upper(i: int) -> str:
    return hex(i)[2:].upper()

def hex_to_int(h: str) -> int:
    return int(h, 16)

__all__ = [
    "sha256_bytes", "sha256_hex",
    "gen_rsa_keypair", "is_probable_prime", "gen_prime",
    "egcd", "modinv",
    "rsa_encrypt_int", "rsa_decrypt_int",
    "sign_bytes_with_rsa", "verify_bytes_with_rsa",
    "int_to_hex_upper", "hex_to_int"
]
