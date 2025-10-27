# server.py
import socket
import threading

def handle_client(client_socket, clients):
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                break
            ciphertext = data.decode('utf-8')
            # Log the ciphertext to logMessage.txt
            with open('logMessage.txt', 'a') as f:
                f.write(ciphertext + '\n')
            # Broadcast to all other clients
            for cl in clients:
                if cl != client_socket:
                    cl.send(data)
        except:
            break
    clients.remove(client_socket)
    client_socket.close()

def main():
    host = input("Enter server IP to bind (e.g., 0.0.0.0 for all interfaces): ").strip()
    port = int(input("Enter port: ").strip())
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"Server listening on {host}:{port}")
    
    clients = []
    
    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        clients.append(client_socket)
        thread = threading.Thread(target=handle_client, args=(client_socket, clients))
        thread.start()

if __name__ == "__main__":
    main()