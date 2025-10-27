# client.py
import socket
import threading
import datetime
import sys
from io import StringIO
from Original import encrypt_message, decrypt_message

KEY = "AABB09182736CCDD"  # Hardcoded shared key; in practice, share securely out-of-band

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            ciphertext = data.decode('utf-8')
            # Log the received ciphertext
            with open('logMessage.txt', 'a') as f:
                f.write(ciphertext + '\n')
            # Capture decryption procedure
            old_stdout = sys.stdout
            log = StringIO()
            sys.stdout = log
            plain_bytes = decrypt_message(ciphertext, KEY)
            sys.stdout = old_stdout
            # Log procedure
            with open('logProcedure.txt', 'a') as f:
                f.write(log.getvalue() + '\n')
            # Display
            try:
                print(plain_bytes.decode('utf-8'))
            except:
                print("Decoding error; raw bytes:", plain_bytes)
        except:
            break

def main():
    username = input("Enter username: ").strip()
    server_ip = input("Enter server IP: ").strip()
    port = int(input("Enter port: ").strip())
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, port))
    
    receive_thread = threading.Thread(target=receive_messages, args=(sock,))
    receive_thread.start()
    
    while True:
        message = input("").strip()
        if not message:
            continue
        now = datetime.datetime.now()
        timestamp = now.strftime("%m-%d-%Y %H:%M:%S")
        formatted = f"[{timestamp}] {username}: {message}"
        print(formatted)  # Display locally
        pt_bytes = formatted.encode('utf-8')
        # Capture encryption procedure
        old_stdout = sys.stdout
        log = StringIO()
        sys.stdout = log
        ciphertext = encrypt_message(pt_bytes, KEY)
        sys.stdout = old_stdout
        # Log procedure
        with open('logProcedure.txt', 'a') as f:
            f.write(log.getvalue() + '\n')
        # Log the ciphertext
        with open('logMessage.txt', 'a') as f:
            f.write(ciphertext + '\n')
        # Send to server
        sock.send(ciphertext.encode('utf-8'))

if __name__ == "__main__":
    main()