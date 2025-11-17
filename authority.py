import socket
import threading
import os
import random
import hashlib
import sys
import json

# ---------- RSA utilities (Miller-Rabin, modinv etc.) ----------
def is_probable_prime(n, k=8):
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
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def gen_rsa_keypair(bits=1024):
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

# ---------- Authority bootstrap ----------
AUTH_BITS = 1024
print("Generating Authority RSA keypair (this may take a second)...")
auth_n, auth_e, auth_d = gen_rsa_keypair(AUTH_BITS)
print("Authority RSA keypair ready.")
AUTH_PUB_E_HEX = hex(auth_e)[2:].upper()
AUTH_PUB_N_HEX = hex(auth_n)[2:].upper()

GROUP_KEY_BYTES = os.urandom(8)
GROUP_KEY_HEX = GROUP_KEY_BYTES.hex().upper()
print("Generated group DES key (hex):", GROUP_KEY_HEX)

registrations_lock = threading.Lock()
REG_FILE = "registrations.json"

def load_registrations():
    if not os.path.exists(REG_FILE):
        return {}
    try:
        with open(REG_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_registration(username, e_hex, n_hex):
    with registrations_lock:
        regs = load_registrations()
        regs[username] = {"e": e_hex, "n": n_hex}
        with open(REG_FILE, "w") as f:
            json.dump(regs, f)

def handle_client(conn, addr):
    with conn:
        try:
            data = conn.recv(8192)
            if not data:
                return
            msg = data.decode('utf-8').strip()
            if not msg.startswith("REGISTER::"):
                conn.send(b"ERROR::BAD_REQUEST")
                return
            parts = msg.split("::")
            if len(parts) != 4:
                conn.send(b"ERROR::BAD_FORMAT")
                return
            _, username, e_hex, n_hex = parts
            client_e = int(e_hex, 16)
            client_n = int(n_hex, 16)

            save_registration(username, e_hex, n_hex)

            m = int(GROUP_KEY_HEX, 16)
            c = pow(m, client_e, client_n)
            c_hex = hex(c)[2:].upper()

            to_sign = (username + GROUP_KEY_HEX).encode('utf-8')
            h = hashlib.sha256(to_sign).hexdigest()
            h_int = int(h, 16)
            sig_int = pow(h_int, auth_d, auth_n)
            sig_hex = hex(sig_int)[2:].upper()

            resp = (
                "KEY::" + c_hex +
                "::AUTH_PUB::" + AUTH_PUB_E_HEX + "::" + AUTH_PUB_N_HEX +
                "::SIG::" + sig_hex +
                "::GROUP_LEN::" + str(len(GROUP_KEY_HEX))
            )
            conn.send(resp.encode('utf-8'))

            with open("authority_registrations.log", "a") as f:
                f.write(f"{addr} REGISTER {username} pub_e={e_hex} pub_n_len={len(n_hex)}\n")

            print(f"[Authority] Registered '{username}' from {addr}")
        except Exception as exc:
            print("[Authority] Error handling client:", exc)

def main():
    host = input("Authority bind IP (0.0.0.0): ").strip() or "0.0.0.0"
    port = int(input("Authority port (e.g. 7000): ").strip() or "7000")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f"Authority listening on {host}:{port}")
    print("Authority public key (e, n) (hex):")
    print("e:", AUTH_PUB_E_HEX)
    print("n:", AUTH_PUB_N_HEX)

    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("Authority shutting down.")
        s.close()
        sys.exit(0)

if __name__ == "__main__":
    main()