import socket
import hashlib

HOST = '127.0.0.1'
PORT = 5000

def compute_hash(message):
    return hashlib.sha256(message).hexdigest()

message = "Hello, this is a message sent in multiple parts!"
message_bytes = message.encode()

parts = [message_bytes[i:i+10] for i in range(0, len(message_bytes), 10)]

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
for part in parts:
    client_socket.sendall(part)


client_socket.shutdown(socket.SHUT_WR)
server_hash = client_socket.recv(1024).decode()
print(f"Hash received from server: {server_hash}")

local_hash = compute_hash(message_bytes)
print(f"Local hash: {local_hash}")

if server_hash == local_hash:
    print("Message integrity verified!")
else:
    print("Message integrity failed!")

client_socket.close()
