import socket
import hashlib

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 5000))

# Message to send
message = "This is a secure message."
client_socket.send(message.encode())

# Receive hash from server
server_hash = client_socket.recv(1024).decode()

# Compute local hash
local_hash = compute_hash(message.encode())

print("Message sent:", message)
print("Local hash: ", local_hash)
print("Server hash:", server_hash)

# Verify integrity
if local_hash == server_hash:
    print("Data integrity verified: No tampering")
else:
    print("Data integrity failed: Data corrupted/tampered")

client_socket.close()
