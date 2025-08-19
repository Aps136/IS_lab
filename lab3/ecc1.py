from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

print("Keys have been securely generated.")

# Message to be encrypted
message = b"Secure Transactions"

# Padder for PKCS7
padder = padding.PKCS7(algorithms.AES.block_size).padder()
padded_message = padder.update(message) + padder.finalize()

shared_secret = private_key.exchange(ec.ECDH(), public_key)

encryption_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'encryption key',
).derive(shared_secret)

iv = os.urandom(16)

# Encrypt with padded message
cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_message) + encryptor.finalize()

print(f"\nOriginal Message: {message.decode('utf-8')}")
print(f"Padded Message: {padded_message}")
print(f"Encrypted Message (Ciphertext): {ciphertext.hex()}")

# Decrypt the ciphertext
decryptor = cipher.decryptor()
padded_decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

# Unpad the message
unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
decrypted_message = unpadder.update(padded_decrypted_message) + unpadder.finalize()

print(f"\nDecrypted Message: {decrypted_message.decode('utf-8')}")

if message == decrypted_message:
    print("\nVerification successful! The original message was restored.")
else:
    print("\nVerification failed. Something went wrong.")
