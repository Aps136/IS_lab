import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# This example uses the P-256 curve, a standard choice for modern applications.
CURVE = ec.SECP256R1()
backend = default_backend()


def generate_key_pair():
    """Generates a private and public key pair for ECC."""
    private_key = ec.generate_private_key(CURVE, backend)
    public_key = private_key.public_key()
    return private_key, public_key


def ecies_encrypt(message, recipient_public_key):
    """
    Encrypts a message using a simplified Elliptic Curve Integrated Encryption Scheme (ECIES).

    1. Generates an ephemeral (temporary) key pair for the sender.
    2. Uses the sender's private key and the recipient's public key to derive a shared secret.
    3. Uses a Key Derivation Function (KDF) to turn the shared secret into a symmetric key.
    4. Encrypts the message using AES with the derived symmetric key.

    Returns the ephemeral public key, the ciphertext, and the initialization vector (IV).
    """
    # 1. Generate an ephemeral key pair for the sender.
    sender_private_key = ec.generate_private_key(CURVE, backend)
    sender_public_key = sender_private_key.public_key()

    # 2. Derive the shared secret using ECDH (Elliptic Curve Diffie-Hellman).
    shared_secret = sender_private_key.exchange(ec.ECDH(), recipient_public_key)

    # 3. Use HKDF to derive a strong symmetric key from the shared secret.
    salt = os.urandom(16)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # For AES-256
        salt=salt,
        info=b'handshake data',
        backend=backend
    ).derive(shared_secret)

    # Generate a random IV for AES encryption
    iv = os.urandom(16)

    # 4. Encrypt the message using AES-256 in CBC mode.
    # Note: For simplicity, this example does not include authentication.
    # A real-world ECIES implementation would use an authenticated mode like GCM.
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Padding the message to be a multiple of the block size
    padded_message = message + (16 - len(message) % 16) * bytes([16 - len(message) % 16])

    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    return sender_public_key, ciphertext, iv, salt


def ecies_decrypt(sender_public_key, ciphertext, iv, salt, recipient_private_key):
    """
    Decrypts a message encrypted with the ECIES-like scheme.

    1. Uses the recipient's private key and the sender's public key to derive the same shared secret.
    2. Uses the same KDF to derive the symmetric key.
    3. Decrypts the message using AES.

    Returns the original plaintext message.
    """
    # 1. Derive the same shared secret using the recipient's private key.
    shared_secret = recipient_private_key.exchange(ec.ECDH(), sender_public_key)

    # 2. Use HKDF with the same salt and info to derive the same symmetric key.
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data',
        backend=backend
    ).derive(shared_secret)

    # 3. Decrypt the message using AES-256 in CBC mode.
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpadding the message
    padding_length = decrypted_padded[-1]
    plaintext = decrypted_padded[:-padding_length]

    return plaintext


# --- Example Usage ---
if __name__ == '__main__':
    # Step 1: Recipient generates their key pair.
    # This key pair is long-lived. The private key remains secret.
    recipient_private_key, recipient_public_key = generate_key_pair()
    print("Recipient's key pair generated successfully.")

    # The message to be encrypted (must be bytes).
    original_message = b"This is a secret message to be encrypted using a hybrid ECC scheme."

    print("\n--- Starting ECIES Encryption ---")
    # Step 2: The sender encrypts the message for the recipient.
    # The sender only needs the recipient's public key.
    sender_public_key_sent, ciphertext, iv_sent, salt_sent = ecies_encrypt(original_message, recipient_public_key)
    print("Message encrypted.")

    # In a real application, the sender would transmit:
    # sender_public_key_sent, ciphertext, iv_sent, salt_sent
    print("\n--- Starting ECIES Decryption ---")
    # Step 3: The recipient decrypts the message.
    # The recipient uses their private key and the sender's public key.
    decrypted_message = ecies_decrypt(sender_public_key_sent, ciphertext, iv_sent, salt_sent, recipient_private_key)

    print("Message decrypted.")

    print("\nOriginal Message:")
    print(original_message.decode())

    print("\nDecrypted Message:")
    print(decrypted_message.decode())

    # Verification
    if original_message == decrypted_message:
        print("\nSUCCESS: The original and decrypted messages match!")
    else:
        print("\nFAILURE: Decryption did not produce the original message.")
