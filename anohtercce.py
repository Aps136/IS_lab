from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

# ----------------------------
# Step 1: Generate RSA key pairs
# ----------------------------
encoder_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
encoder_public_key = encoder_private_key.public_key()

decoder_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
decoder_public_key = decoder_private_key.public_key()

# Function to serialize keys for display
def serialize_key(key, private=False):
    if private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

print("=== RSA Key Pairs ===")
print("\nEncoder Public Key:\n", serialize_key(encoder_public_key))
print("Encoder Private Key:\n", serialize_key(encoder_private_key, private=True))
print("Decoder Public Key:\n", serialize_key(decoder_public_key))
print("Decoder Private Key:\n", serialize_key(decoder_private_key, private=True))

# ----------------------------
# Step 2: Generate AES-128 session key
# ----------------------------
aes_key = os.urandom(16)  # 16 bytes = 128 bits
print("\nAES-128 Session Key (original):", aes_key.hex())

# ----------------------------
# Step 3: Encrypt AES key with Decoder's public key
# ----------------------------
encrypted_aes_key = decoder_public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("\nEncrypted AES Key:", encrypted_aes_key.hex())

# ----------------------------
# Step 4: Decrypt AES key with Decoder's private key
# ----------------------------
decrypted_aes_key = decoder_private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("\nDecrypted AES Key:", decrypted_aes_key.hex())

# Verify
print("\nMatch?", aes_key == decrypted_aes_key)
