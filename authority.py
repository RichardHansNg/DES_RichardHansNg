import socket
import threading
import os
import sys
import json

from cryptosystem import (
    gen_rsa_keypair,
    rsa_encrypt_int,
    sign_bytes_with_rsa,
    int_to_hex_upper
)

# ---------- Authority bootstrap ----------
AUTH_BITS = 2048
print("Generating Authority RSA keypair (this may take a while)...")
auth_n, auth_e, auth_d = gen_rsa_keypair(AUTH_BITS)
print("Authority RSA keypair ready.")
AUTH_PUB_E_HEX = int_to_hex_upper(auth_e)
AUTH_PUB_N_HEX = int_to_hex_upper(auth_n)

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
            try:
                client_e = int(e_hex, 16)
                client_n = int(n_hex, 16)
            except Exception:
                conn.send(b"ERROR::BAD_PUBKEY")
                return

            save_registration(username, e_hex, n_hex)

            m = int(GROUP_KEY_HEX, 16)
            c_int = rsa_encrypt_int(m, client_e, client_n)
            c_hex = int_to_hex_upper(c_int)

            to_sign = (username + GROUP_KEY_HEX).encode('utf-8')
            sig_hex = sign_bytes_with_rsa(auth_d, auth_n, to_sign)

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
