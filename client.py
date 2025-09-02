import socket
import hashlib

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

def client(message):
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(message.encode())

        # Receive hash from server
        server_hash = s.recv(1024).decode()
        print(f"Hash received from server: {server_hash}")

        # Compute local hash
        local_hash = compute_hash(message.encode())
        print(f"Local hash: {local_hash}")

        if local_hash == server_hash:
            print("Data integrity verified: hashes match.")
        else:
            print("Data corrupted or tampered: hashes do not match.")

if __name__ == "__main__":
    # Change message to simulate corruption and test
    client("Hello, Secure World!")
