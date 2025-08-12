from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

print("Keys have been securely generated.")

message = b"Secure Transactions"

shared_secret = private_key.exchange(ec.ECDH(), public_key)

encryption_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'encryption key',
).derive(shared_secret)

iv = os.urandom(16)

cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()

print(f"\nOriginal Message: {message.decode('utf-8')}")
print(f"Encrypted Message (Ciphertext): {ciphertext}")

decryptor = cipher.decryptor()
decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

print(f"\nDecrypted Message: {decrypted_message.decode('utf-8')}")

if message == decrypted_message:
    print("\nVerification successful! The original message was restored.")
else:
    print("\nVerification failed. Something went wrong.")
