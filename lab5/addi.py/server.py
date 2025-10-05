import socket
import hashlib

HOST = '127.0.0.1'
PORT = 5000

def compute_hash(message):
    return hashlib.sha256(message).hexdigest()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print(f"Server listening on {HOST}:{PORT}...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Receive message parts
full_message = b''
while True:
    data = conn.recv(1024)
    if not data:
        break
    full_message += data


message_hash = compute_hash(full_message)
print(f"Reassembled message: {full_message.decode()}")
print(f"Hash: {message_hash}")
conn.sendall(message_hash.encode())

conn.close()
server_socket.close()
