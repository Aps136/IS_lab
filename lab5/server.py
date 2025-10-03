import socket
import hashlib

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

# Create TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 5000))
server_socket.listen(1)

print("Server is listening on port 5000...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Receive data
data = conn.recv(1024)
print("Server received:", data.decode())

# Compute hash of received data
hash_value = compute_hash(data)
print("Server computed hash:", hash_value)

# Send hash back to client
conn.send(hash_value.encode())

conn.close()
