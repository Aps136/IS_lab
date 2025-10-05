import socket
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
import pickle

# ------------------- Schnorr verify -------------------
def schnorr_verify(message_hash, signature, public_key, p, g, q):
    r, s = signature
    e = int(sha256((str(r) + message_hash).encode()).hexdigest(), 16) % q
    g_s = pow(g, s, p)
    y_e = pow(public_key, e, p)
    return (g_s * y_e) % p == r % p

# ------------------- Setup -------------------
HOST = "localhost"
PORT = 5000

p, q, g = 115, 340, 2
schnorr_private_key, schnorr_public_key = 37, 91

aes_key = b"FEDCBA9876543210FEDCBA9876543210"

# Create TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print("Server listening on port", PORT)

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Receive data
data = conn.recv(4096)
signature, ciphertext = pickle.loads(data)

# Decrypt message
cipher = AES.new(aes_key, AES.MODE_ECB)
decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
message = decrypted.decode()

# Compute SHA-256 hash
message_hash = hashlib.sha256(message.encode()).hexdigest()

# Verify Schnorr signature
is_valid = schnorr_verify(message_hash, signature, schnorr_public_key, p, g, q)

print("Decrypted message:", message)
print("SHA-256 Hash:", message_hash)
print("Schnorr Signature valid:", is_valid)
print("Message integrity:", "Message authentic and untampered ✅" if is_valid else "Warning: Message integrity failed ❌")

conn.close()
server_socket.close()
