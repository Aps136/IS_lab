from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os
import time
import matplotlib.pyplot as plt

# ----------------------------
# Parameters
# ----------------------------
message = b"Information Security Lab evaluation one"
aes_key_128 = b"0123456789ABCDEF0123456789ABCDEF"[:16]  # AES-128 requires 16 bytes
iv = os.urandom(16)  # Random IV for AES

# ----------------------------
# AES-128 Encryption
# ----------------------------
start_time_aes = time.time()
cipher = Cipher(algorithms.AES(aes_key_128), modes.CBC(iv))
encryptor = cipher.encryptor()
# Pad message to multiple of 16 bytes
padding_len = 16 - len(message) % 16
padded_message = message + bytes([padding_len] * padding_len)
ciphertext_aes = encryptor.update(padded_message) + encryptor.finalize()
end_time_aes = time.time()
aes_time = end_time_aes - start_time_aes

# Decrypt AES
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext_aes) + decryptor.finalize()
# Remove padding
decrypted_message = decrypted_padded[:-decrypted_padded[-1]]
print("AES Decrypted Message:", decrypted_message)

# ----------------------------
# Hybrid Encryption (AES + RSA)
# ----------------------------
# RSA keys for decoder
decoder_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
decoder_public_key = decoder_private_key.public_key()

# Encrypt AES key using RSA (simulate hybrid encryption)
start_time_hybrid = time.time()
encrypted_aes_key = decoder_public_key.encrypt(
    aes_key_128,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
end_time_hybrid = time.time()
rsa_time = end_time_hybrid - start_time_hybrid

# Decrypt AES key with RSA
decrypted_aes_key = decoder_private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

print("AES key matches after RSA decryption:", aes_key_128 == decrypted_aes_key)

# ----------------------------
# Plot comparison
# ----------------------------
methods = ['AES-128', 'RSA Encrypt AES Key']
times = [aes_time, rsa_time]

plt.bar(methods, times, color=['blue', 'orange'])
plt.ylabel("Time (seconds)")
plt.title("Encryption Time Comparison")
plt.show()
