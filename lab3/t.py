import time
import random
import numpy as np
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

# ------------------------------
# Hill Cipher (2x2 matrix demo)
# ------------------------------
def hill_encrypt(message, key_matrix):
    # Remove spaces & lowercase
    message = message.replace(" ", "").lower()
    n = len(key_matrix)
    # pad
    while len(message) % n != 0:
        message += "x"
    # mappings
    char_to_num = {chr(i+97): i for i in range(26)}
    num_to_char = {i: chr(i+97) for i in range(26)}

    ciphertext = ""
    for i in range(0, len(message), n):
        block = message[i:i+n]
        vector = np.array([char_to_num[c] for c in block])
        result = np.dot(key_matrix, vector) % 26
        ciphertext += "".join(num_to_char[int(x)] for x in result)
    return ciphertext

# ------------------------------
# AES Encryption
# ------------------------------
def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(message.encode(), AES.block_size))
    return ct

# ------------------------------
# RSA Encryption
# ------------------------------
def rsa_encrypt(message, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(message.encode())

# ------------------------------
# Main Timing Comparison
# ------------------------------
message = "This is a performance test of encryption algorithms"

# Hill cipher key (2x2 invertible matrix mod 26)
key_matrix = np.array([[3, 3], [2, 5]])

# AES key (128-bit)
aes_key = os.urandom(16)

# RSA key pair (2048-bit)
rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey()

# --- Hill Cipher timing
start = time.time()
hill_ct = hill_encrypt(message, key_matrix)
hill_time = time.time() - start

# --- AES timing
start = time.time()
aes_ct = aes_encrypt(message, aes_key)
aes_time = time.time() - start

# --- RSA timing
start = time.time()
rsa_ct = rsa_encrypt(message, public_key)
rsa_time = time.time() - start

# ------------------------------
# Plot results
# ------------------------------
algorithms = ["Hill Cipher", "AES-128", "RSA-2048"]
times = [hill_time, aes_time, rsa_time]

plt.bar(algorithms, times, color=["blue","green","red"])
plt.ylabel("Time (seconds)")
plt.title("Encryption Time Comparison")
plt.show()

# Print results
print("Hill Cipher time:", hill_time)
print("AES-128 time:", aes_time)
print("RSA-2048 time:", rsa_time)
