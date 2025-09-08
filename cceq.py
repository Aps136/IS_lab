import time
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ----------------------------
# Technique 1: Simple Vigenère-like Cipher
# ----------------------------
def genkey(text, key):
    repeated = ''
    for i in range(len(text)):
        repeated += key[i % len(key)]
    return repeated

def encode(text, key):
    encoded = ''
    repeated = genkey(text, key)
    idx = 0
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            val = ord(char) - shift_base
            kval = ord(repeated[idx].upper()) - 65
            encoded += chr((val + kval) % 26 + shift_base)
            idx += 1
        else:
            encoded += char
    return encoded

def decode(text, key):
    decoded = ''
    repeated = genkey(text, key)
    idx = 0
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            val = ord(char) - shift_base
            kval = ord(repeated[idx].upper()) - 65
            decoded += chr((val - kval + 26) % 26 + shift_base)
            idx += 1
        else:
            decoded += char
    return decoded

text = "the key is hidden under the mattress"
key1 = "POTATO"
start1 = time.time()
encoded_text = encode(text, key1)
end1 = time.time()
decoded_text = decode(encoded_text, key1)
time1 = end1 - start1
print("\nTechnique 1 (Vigenère-like) Cipher:")
print("Cipher text:", encoded_text)
print("Decrypted text:", decoded_text)
print("Time:", time1)

# ----------------------------
# Technique 2: Hybrid AES-128 + RSA key sharing
# ----------------------------

# Generate RSA key pairs
encoder_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
encoder_public_key = encoder_private_key.public_key()
decoder_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
decoder_public_key = decoder_private_key.public_key()

# AES-128 key
aes_key = os.urandom(16)
message2 = b"Information security lab evaluation one"

start2 = time.time()
# Encrypt AES key with RSA
encrypted_aes_key = decoder_public_key.encrypt(
    aes_key,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# Decrypt AES key
decrypted_aes_key = decoder_private_key.decrypt(
    encrypted_aes_key,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
end2 = time.time()
time2 = end2 - start2
print("\nTechnique 2 (AES-128 key shared via RSA):")
print("Original AES key:", aes_key.hex())
print("Encrypted AES key:", encrypted_aes_key.hex()[:60] + "...")
print("Decrypted AES key:", decrypted_aes_key.hex())
print("Time:", time2)

# ----------------------------
# Technique 3: Direct AES-128 Encryption
# ----------------------------
key3 = b"0123456789ABCDEF"  # 16 bytes for AES-128
start3 = time.time()
cipher = AES.new(key3, AES.MODE_ECB)
padded_message = pad(message2, AES.block_size)
ciphertext = cipher.encrypt(padded_message)
decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
end3 = time.time()
time3 = end3 - start3
print("\nTechnique 3 (Direct AES-128 ECB):")
print("Cipher text:", ciphertext.hex())
print("Decrypted text:", decrypted_message.decode())
print("Time:", time3)

# ----------------------------
# Plotting encryption times
# ----------------------------
methods = ['Vigenère-like', 'AES+RSA', 'AES-128']
times = [time1, time2, time3]

plt.bar(methods, times, color=['blue', 'orange', 'green'])
plt.ylabel("Time (seconds)")
plt.title("Encryption Time Comparison")
plt.show()
