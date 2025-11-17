import socket
import threading
import sys
import traceback
import json
import os
import datetime

REG_FILE = "registrations.json"
LOG_FILE = "server_logMessage.txt"

def try_set_reuse_options(s):
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 0)
        except Exception:
            pass

def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except:
            return None
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
    return data

def send_framed(sock, data_bytes):
    hdr = len(data_bytes).to_bytes(4, 'big')
    sock.sendall(hdr + data_bytes)

def load_registrations():
    if not os.path.exists(REG_FILE):
        return {}
    try:
        with open(REG_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def verify_signature(username, ciphertext_hex, sig_hex):
    regs = load_registrations()
    info = regs.get(username)
    if not info:
        return False, "UNREGISTERED"
    try:
        e = int(info['e'], 16)
        n = int(info['n'], 16)
        sig_int = int(sig_hex, 16)
        import hashlib
        h = hashlib.sha256(ciphertext_hex.encode('utf-8')).hexdigest()
        h_int = int(h, 16)
        verification = pow(sig_int, e, n)
        if verification == (h_int % n):
            return True, "VERIFIED"
        else:
            return False, "FAILED"
    except Exception:
        return False, "ERROR"

def log_server_entry(timestamp, username, status, sig_hex, ciphertext_hex):
    line = f"{timestamp} | {username} | {status} | sig={sig_hex} | {ciphertext_hex}\n"
    with open(LOG_FILE, "a") as f:
        f.write(line)

def handle_client(client_socket, clients, lock):
    try:
        while True:
            raw = recv_framed(client_socket)
            if raw is None:
                break
            try:
                payload = json.loads(raw.decode('utf-8'))
                username = payload.get("username", "<unknown>")
                ciphertext_hex = payload.get("ciphertext", "")
                sig_hex = payload.get("sig", "")
            except Exception:
                username = "<malformed>"
                ciphertext_hex = raw.hex()
                sig_hex = ""
            ok, status = verify_signature(username, ciphertext_hex, sig_hex)
            timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            log_server_entry(timestamp, username, status, sig_hex, ciphertext_hex)

            with lock:
                dead = []
                for cl in clients:
                    if cl is not client_socket:
                        try:
                            send_framed(cl, raw)
                        except Exception:
                            dead.append(cl)
                for d in dead:
                    if d in clients:
                        try:
                            d.close()
                        except:
                            pass
                        clients.remove(d)
    except Exception:
        traceback.print_exc()
    finally:
        with lock:
            if client_socket in clients:
                clients.remove(client_socket)
        try:
            client_socket.close()
        except:
            pass

def main():
    default_host = "127.0.0.1"
    host = input(f"Enter server IP to bind (default {default_host}): ").strip() or default_host

    while True:
        port_input = input("Enter port (e.g., 8000): ").strip()
        try:
            port = int(port_input)
            if not (0 < port < 65536):
                raise ValueError
            break
        except ValueError:
            print("Invalid port. Please enter a number between 1 and 65535.")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try_set_reuse_options(server)

    while True:
        try:
            server.bind((host, port))
            break
        except OSError as e:
            print(f"Bind failed: {e}")
            new_port = input("Enter a different port to try, or press Enter to abort: ").strip()
            if not new_port:
                server.close()
                return
            try:
                port = int(new_port)
            except ValueError:
                print("Invalid port; aborting.")
                server.close()
                return

    server.listen(5)
    print(f"Server listening on {host}:{port}")
    clients = []
    clients_lock = threading.Lock()

    try:
        while True:
            client_socket, addr = server.accept()
            print(f"Accepted connection from {addr}")
            with clients_lock:
                clients.append(client_socket)
            thread = threading.Thread(target=handle_client, args=(client_socket, clients, clients_lock), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down (KeyboardInterrupt). Closing sockets...")
    finally:
        with clients_lock:
            for c in clients:
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    c.close()
                except:
                    pass
            clients.clear()
        try:
            server.close()
        except:
            pass
        print("Server closed cleanly.")

if __name__ == "__main__":
    main()
