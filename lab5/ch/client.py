import socket
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long
from hashlib import sha256

# ------------------- Schnorr functions -------------------
def schnorr_sign(message_hash, private_key, p, g, q):
    x = private_key
    k = bytes_to_long(get_random_bytes(32)) % q
    r = pow(g, k, p)
    e = int(sha256((str(r) + message_hash).encode()).hexdigest(), 16) % q
    s = (k - x * e) % (p-1)
    return (r, s)

# ------------------- Setup -------------------
HOST = "localhost"
PORT = 5000

p, q, g = 115, 340, 2
schnorr_private_key, schnorr_public_key = 37, 91

aes_key = b"FEDCBA9876543210FEDCBA9876543210"  # 32 bytes = AES-256

message = "This is a secure message."

# Compute SHA-256 hash of message
message_hash = hashlib.sha256(message.encode()).hexdigest()

# Sign the hash
signature = schnorr_sign(message_hash, schnorr_private_key, p, g, q)

# Encrypt the message using AES
cipher = AES.new(aes_key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

# Send data to server
import pickle
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
client_socket.send(pickle.dumps((signature, ciphertext)))

print("Message sent:", message)
print("SHA-256 Hash:", message_hash)
print("Schnorr Signature:", signature)

client_socket.close()
