from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import time

# --- Key Generation for recipient ---
recipient_private_key = ec.generate_private_key(ec.SECP256R1())
recipient_public_key = recipient_private_key.public_key()

# --- EC-ElGamal Encryption ---
def ec_elgamal_encrypt(public_key, plaintext: bytes):
    # Generate ephemeral key
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    shared_point = ephemeral_key.exchange(ec.ECDH(), public_key)

    # Derive symmetric key from shared point
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ec-elgamal',
    ).derive(shared_point)

    # Encrypt plaintext using AES-GCM
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    # Send ephemeral public key + ciphertext + iv + tag
    ephemeral_pub_bytes = ephemeral_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    return ephemeral_pub_bytes, iv, ciphertext, tag

# --- EC-ElGamal Decryption ---
def ec_elgamal_decrypt(private_key, ephemeral_pub_bytes, iv, ciphertext, tag):
    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_pub_bytes
    )
    shared_point = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Derive symmetric key
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ec-elgamal',
    ).derive(shared_point)

    # Decrypt using AES-GCM
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# --- Test encryption/decryption ---
patient_data = b"Patient: John Doe\nDiagnosis: Hypertension\nPrescriptions: Medication A"
print("Original data:", patient_data)

# Measure encryption
start_enc = time.time()
ephemeral_pub, iv, ciphertext, tag = ec_elgamal_encrypt(recipient_public_key, patient_data)
end_enc = time.time()
print(f"Encryption time: {end_enc - start_enc:.6f} sec")
print("Ciphertext:", ciphertext.hex())

# Measure decryption
start_dec = time.time()
decrypted_data = ec_elgamal_decrypt(recipient_private_key, ephemeral_pub, iv, ciphertext, tag)
end_dec = time.time()
print(f"Decryption time: {end_dec - start_dec:.6f} sec")
print("Decrypted data:", decrypted_data)
