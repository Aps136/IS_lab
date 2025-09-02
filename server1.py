import socket
import hashlib

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

def server():
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()

        print("Server listening...")
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            data = conn.recv(1024)
            if not data:
                return
            print(f"Received data: {data.decode()}")

            # Compute hash
            hash_val = compute_hash(data)
            print(f"Computed hash: {hash_val}")

            # Send hash back to client
            conn.sendall(hash_val.encode())

if __name__ == "__main__":
    server()
