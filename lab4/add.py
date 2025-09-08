from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os

# Generate Decoder's RSA keys
decoder_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
decoder_public_key = decoder_private_key.public_key()

# Generate random AES key
aes_key = os.urandom(32)  # 256-bit

# Encrypt AES key with Decoder's public key
encrypted_aes_key = decoder_public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Decrypt AES key with Decoder's private key
decrypted_aes_key = decoder_private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Check if decryption worked
print("Keys match:", aes_key == decrypted_aes_key)
