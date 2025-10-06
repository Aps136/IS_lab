from helper import *
import time
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

# ==============================================================================
# --- Question 1: RSA Encryption and Decryption ---
# ==============================================================================
print("--- Question 1: RSA ---")
pt1 = b"Asymmetric Encryption"

# 1. Generate RSA key pair (private_key, public_key)
private_key_rsa, public_key_rsa = rsa_key(bits=2048)

# 2. Encrypt with the public key
ct1 = rsa_enc(pt1, public_key_rsa)

# 3. Decrypt with the private key
decrypted_pt1 = rsa_dec(ct1, private_key_rsa)

print(f"Plaintext: {pt1.decode()}")
print(f"Public Key (n, e): ({public_key_rsa.n:x}, {public_key_rsa.e})")
print(f"Ciphertext (hex): {ct1.hex()}")
print(f"Decrypted Text: {decrypted_pt1.decode()}")
print("-" * 25, "\n")


# ==============================================================================
# --- Question 2: ECC Encryption and Decryption ---
# ==============================================================================
print("--- Question 2: ECC ---")
pt2 = b"Secure Transactions"

# 1. Generate recipient's ECC key pair
recipient_key_ecc = ECC.generate(curve='P-256')
recipient_pub_key = recipient_key_ecc.public_key()

# 2. Encrypt with the recipient's public key
# This returns multiple components needed for decryption
ephemeral_key_der, iv, ct2, tag = ecies_enc(pt2, recipient_pub_key)

# 3. Decrypt with the recipient's private key
decrypted_pt2 = ecies_dec(ephemeral_key_der, iv, ct2, tag, recipient_key_ecc)

print(f"Plaintext: {pt2.decode()}")
print(f"Ciphertext (components):")
print(f"  - Ephemeral Key: {ephemeral_key_der.hex()}")
print(f"  - IV: {iv.hex()}")
print(f"  - Tag: {tag.hex()}")
print(f"  - Ciphertext: {ct2.hex()}")
print(f"Decrypted Text: {decrypted_pt2.decode()}")
print("-" * 25, "\n")


# ==============================================================================
# --- Question 3: ElGamal Encryption and Decryption ---
# ==============================================================================
print("--- Question 3: ElGamal ---")
pt3_str = "Confidential Data"
# ElGamal works on integers, so we convert our bytes to a large integer
pt3_int = int.from_bytes(pt3_str.encode('utf-8'), 'big')

# 1. Generate ElGamal keys (public key is p, g, h; private is x)
p, g, h, x = elg_key(bits=256)

# 2. Encrypt with the public key
c1, c2 = elg_enc(pt3_int, p, g, h)

# 3. Decrypt with the private key
decrypted_pt3_int = elg_dec(c1, c2, p, x)

# Convert the decrypted integer back to a string
decrypted_pt3_str = decrypted_pt3_int.to_bytes((decrypted_pt3_int.bit_length() + 7) // 8, 'big').decode('utf-8')

print(f"Plaintext: {pt3_str}")
print(f"Public Key (p, g, h): ({p}, {g}, {h})")
print(f"Private Key (x): {x}")
print(f"Ciphertext (c1, c2): ({c1}, {c2})")
print(f"Decrypted Text: {decrypted_pt3_str}")
print("-" * 25, "\n")


# ==============================================================================
# --- Question 4: RSA vs. ECC Performance for File Transfer ---
# ==============================================================================
print("--- Question 4: RSA vs ECC Performance Analysis ---")
file_size_mb = 1
file_data = get_random_bytes(1024 * 1024 * file_size_mb)
print(f"Testing with a file of {file_size_mb} MB...\n")

# --- Key Generation ---
print("1. Key Generation Time:")
start_time = time.perf_counter()
rsa_private, rsa_public = rsa_key(bits=2048)
rsa_gen_time = time.perf_counter() - start_time
print(f"   - RSA 2048-bit Key Generation: {rsa_gen_time:.4f} seconds")

start_time = time.perf_counter()
ecc_private = ECC.generate(curve='P-256')
ecc_public = ecc_private.public_key()
ecc_gen_time = time.perf_counter() - start_time
print(f"   - ECC P-256 Key Generation:    {ecc_gen_time:.4f} seconds\n")

# --- Hybrid Encryption Performance ---
# Asymmetric crypto is too slow for large files. We use a hybrid approach:
# 1. Generate a random symmetric key (AES).
# 2. Encrypt the file with AES.
# 3. Encrypt the AES key with the asymmetric public key.

print("2. Encryption/Decryption Speed:")
aes_key = get_random_bytes(32)  # AES-256 key
iv_aes = get_random_bytes(16)

# RSA Hybrid Encryption
start_time = time.perf_counter()
encrypted_aes_key_rsa = rsa_enc(aes_key, rsa_public)
encrypted_file_aes = aes_cbc_enc(file_data, aes_key, iv_aes)
rsa_enc_time = time.perf_counter() - start_time
print(f"   - RSA Hybrid Encryption: {rsa_enc_time:.4f} seconds")

# RSA Hybrid Decryption
start_time = time.perf_counter()
decrypted_aes_key_rsa = rsa_dec(encrypted_aes_key_rsa, rsa_private)
decrypted_file_aes = aes_cbc_dec(encrypted_file_aes, decrypted_aes_key_rsa, iv_aes)
rsa_dec_time = time.perf_counter() - start_time
print(f"   - RSA Hybrid Decryption: {rsa_dec_time:.4f} seconds")

# ECC Hybrid Encryption (ECIES)
start_time = time.perf_counter()
eph_key, iv_ecc, enc_file_ecc, tag_ecc = ecies_enc(file_data, ecc_public)
ecc_enc_time = time.perf_counter() - start_time
print(f"   - ECC Hybrid Encryption: {ecc_enc_time:.4f} seconds")

# ECC Hybrid Decryption (ECIES)
start_time = time.perf_counter()
dec_file_ecc = ecies_dec(eph_key, iv_ecc, enc_file_ecc, tag_ecc, ecc_private)
ecc_dec_time = time.perf_counter() - start_time
print(f"   - ECC Hybrid Decryption: {ecc_dec_time:.4f} seconds\n")

print("3. Findings and Evaluation:")
print("""
**Performance Summary:**
* **Key Generation**: ECC is significantly faster at generating keys than RSA.
* **Encryption**: ECC is typically faster than RSA, especially as the underlying hybrid system (ECIES) is highly optimized.
* **Decryption**: RSA decryption is computationally intensive and is significantly slower than ECC decryption.

**Security and Efficiency Analysis:**
* **Key Size**: For a similar level of security, ECC keys are much smaller. An ECC key of 256 bits provides security comparable to a 3072-bit RSA key. This means less storage and faster transmission.
* **Computational Overhead**: ECC requires less computational power, making it ideal for devices with limited resources like mobile phones and IoT devices. RSA's slow decryption can be a bottleneck in high-traffic servers.
* **Resistance to Attacks**: Both are secure against current classical computers when using appropriate key sizes. However, ECC is considered more resilient per bit, offering better security for smaller key sizes.

**Conclusion for Secure File Transfer:**
For most modern applications, **ECC is the superior choice**. Its smaller key sizes, faster key generation, and faster cryptographic operations (especially decryption) result in a more efficient and less resource-intensive system without compromising security. RSA remains a valid and secure option but is increasingly being superseded by ECC in new systems.
""")
print("-" * 25, "\n")


# ==============================================================================
# --- Question 5: Diffie-Hellman Key Exchange ---
# ==============================================================================
print("--- Question 5: Diffie-Hellman Key Exchange ---")

# 1. Setup: Agree on public parameters (p, g)
start_time = time.perf_counter()
p, g = dh_params(bits=512)
param_gen_time = time.perf_counter() - start_time
print(f"Public Parameter Generation Time: {param_gen_time:.4f} seconds")
print(f"Public p: {p}")
print(f"Public g: {g}\n")

# 2. Alice generates her keys
start_time = time.perf_counter()
alice_private, alice_public = dh_keypair(p, g)
alice_gen_time = time.perf_counter() - start_time
print(f"Alice's Key Generation Time: {alice_gen_time:.4f} seconds")

# 3. Bob generates his keys
start_time = time.perf_counter()
bob_private, bob_public = dh_keypair(p, g)
bob_gen_time = time.perf_counter() - start_time
print(f"Bob's Key Generation Time: {bob_gen_time:.4f} seconds\n")

# 4. Key Exchange and Shared Secret Calculation
start_time = time.perf_counter()
# Alice computes the secret with her private key and Bob's public key
shared_secret_alice = dh_shared(p, alice_private, bob_public)
# Bob computes the secret with his private key and Alice's public key
shared_secret_bob = dh_shared(p, bob_private, alice_public)
exchange_time = time.perf_counter() - start_time

print(f"Key Exchange (Shared Secret Calculation) Time: {exchange_time:.4f} seconds")
print(f"Alice's Computed Secret: {shared_secret_alice}")
print(f"Bob's Computed Secret:   {shared_secret_bob}")

assert shared_secret_alice == shared_secret_bob
print("\n✅ Success! Both peers computed the same shared secret key.")
print("-" * 25, "\n")
