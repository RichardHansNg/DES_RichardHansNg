import socket
import threading
import datetime
import sys
from io import StringIO
import hashlib
import random
import json

from Original import encrypt_message, decrypt_message

# ---------------- RSA utilities (from scratch) ---------------- #
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

# ---------------- Framing helpers ---------------- #
def send_framed(sock, text):
    data = text.encode('utf-8')
    hdr = len(data).to_bytes(4, 'big')
    sock.sendall(hdr + data)

def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def recv_framed(sock):
    hdr = recv_exact(sock, 4)
    if not hdr:
        return None
    length = int.from_bytes(hdr, 'big')
    data = recv_exact(sock, length)
    if data is None:
        return None
    return data.decode('utf-8', errors='ignore')

# ---------------- Authority registration ---------------- #
def request_group_key_from_authority(authority_ip, authority_port, username, client_e_hex, client_n_hex):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((authority_ip, authority_port))
        reg_msg = f"REGISTER::{username}::{client_e_hex}::{client_n_hex}"
        s.send(reg_msg.encode('utf-8'))
        resp = s.recv(16384).decode('utf-8')
        return resp

def parse_authority_response(resp):
    parts = resp.split("::")
    mapping = {}
    i = 0
    while i < len(parts):
        key = parts[i]
        if key == "KEY":
            mapping["enc"] = parts[i+1]
            i += 2
        elif key == "AUTH_PUB":
            mapping["auth_e"] = parts[i+1]
            mapping["auth_n"] = parts[i+2]
            i += 3
        elif key == "SIG":
            mapping["sig"] = parts[i+1]
            i += 2
        elif key == "GROUP_LEN":
            mapping["group_len"] = int(parts[i+1])
            i += 2
        else:
            i += 1
    return mapping

KEY = None

def receive_messages(sock):
    global KEY
    while True:
        try:
            msg = recv_framed(sock)
            if msg is None:
                print("[receive] connection closed by server.")
                break

            try:
                payload = json.loads(msg)
                sender = payload.get("username", "<unknown>")
                ciphertext = payload.get("ciphertext", "")
                sig = payload.get("sig", "")
            except Exception:
                with open('logProcedure.txt', 'a') as f:
                    f.write(f"[receive] Malformed JSON received: {repr(msg)}\n")
                print("[receive] Malformed payload received (not JSON).")
                continue

            with open('logMessage.txt', 'a') as f:
                f.write(ciphertext + '\n')

            if KEY is None:
                print("[!] No symmetric key established; cannot decrypt incoming message.")
                continue

            old_stdout = sys.stdout
            log = StringIO()
            sys.stdout = log
            try:
                plain_bytes = decrypt_message(ciphertext, KEY)
            except Exception as e:
                plain_bytes = None
                print("[decrypt error]", e)
            sys.stdout = old_stdout
            with open('logProcedure.txt', 'a') as f:
                f.write(log.getvalue() + '\n')

            if plain_bytes is None:
                print("[!] Could not decrypt message from", sender)
            else:
                try:
                    print(plain_bytes.decode('utf-8'))
                except:
                    print("Decoding error; raw bytes:", plain_bytes)
        except Exception as e:
            print("Receive thread error:", e)
            break

def main():
    global KEY
    username = input("Enter username: ").strip()

    print("Generating client's RSA keypair (this may take a second)...")
    client_n, client_e, client_d = gen_rsa_keypair(1024)
    client_e_hex = hex(client_e)[2:].upper()
    client_n_hex = hex(client_n)[2:].upper()
    print("Client RSA keypair ready.")

    authority_ip = input("Authority IP (e.g. 127.0.0.1): ").strip() or "127.0.0.1"
    authority_port = int(input("Authority port (e.g. 7000): ").strip())

    resp = request_group_key_from_authority(authority_ip, authority_port, username, client_e_hex, client_n_hex)
    mapping = parse_authority_response(resp)
    if "enc" not in mapping:
        print("Failed to get key from authority. Response:", resp)
        return

    enc_hex = mapping["enc"]
    auth_e_hex = mapping.get("auth_e")
    auth_n = mapping.get("auth_n")
    sig_hex = mapping.get("sig")
    group_len = mapping.get("group_len", 16)

    c_int = int(enc_hex, 16)
    m_int = pow(c_int, client_d, client_n)
    group_key_hex = format(m_int, 'x').upper().rjust(group_len, '0')
    print("Received group DES key (hex):", group_key_hex)

    if auth_e_hex is None or auth_n is None or sig_hex is None:
        print("Authority didn't provide pubkey or signature.")
        return

    auth_e = int(auth_e_hex, 16)
    auth_n_int = int(auth_n, 16)
    sig_int = int(sig_hex, 16)
    to_verify = (username + group_key_hex).encode('utf-8')
    h = hashlib.sha256(to_verify).hexdigest()
    h_int = int(h, 16)
    verification = pow(sig_int, auth_e, auth_n_int)
    if verification != (h_int % auth_n_int):
        print("Signature verification FAILED. Aborting.")
        return
    print("Signature verified. Authority vouches for the group key.")

    KEY = group_key_hex
    print("Symmetric KEY established.")

    server_ip = input("Enter chat server IP (default 127.0.0.1): ").strip() or "127.0.0.1"
    port = int(input("Enter chat server port (e.g. 8000): ").strip())

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, port))
    receive_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    receive_thread.start()

    try:
        while True:
            message = input("").strip()
            if not message:
                continue
            now = datetime.datetime.now()
            timestamp = now.strftime("%m-%d-%Y %H:%M:%S")
            formatted = f"[{timestamp}] {username}: {message}"
            print(formatted)
            pt_bytes = formatted.encode('utf-8')
            old_stdout = sys.stdout
            log = StringIO()
            sys.stdout = log
            ciphertext = encrypt_message(pt_bytes, KEY)
            sys.stdout = old_stdout
            with open('logProcedure.txt', 'a') as f:
                f.write(log.getvalue() + '\n')

            h = hashlib.sha256(ciphertext.encode('utf-8')).hexdigest()
            h_int = int(h, 16)
            sig_int = pow(h_int, client_d, client_n)
            sig_hex = hex(sig_int)[2:].upper()

            payload = {
                "username": username,
                "ciphertext": ciphertext,
                "sig": sig_hex
            }
            payload_str = json.dumps(payload)
            with open('logMessage.txt', 'a') as f:
                f.write(ciphertext + '\n')
            send_framed(sock, payload_str)
    except (KeyboardInterrupt, EOFError):
        print("Client exiting.")
    except Exception as e:
        print("Client error:", e)
    finally:
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    main()
