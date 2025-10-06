from helper import *
from Crypto.Random import get_random_bytes

# ==============================================================================
# --- Question 1: DES Encryption and Decryption ---
# ==============================================================================
print("--- Question 1: DES ---")
# Define the plaintext and key as bytes
pt1 = b"Confidential Data"
key1 = b"A1B2C3D4"  # DES uses an 8-byte (64-bit) key

# Encrypt the message
ct1 = des_enc(pt1, key1)
# Decrypt the ciphertext
decrypted_pt1 = des_dec(ct1, key1)

print(f"Plaintext: {pt1.decode()}")
print(f"Key: {key1.decode()}")
# Print ciphertext in hexadecimal for readability
print(f"Ciphertext (hex): {ct1.hex()}")
print(f"Decrypted Text: {decrypted_pt1.decode()}")
print("-" * 25, "\n")


# ==============================================================================
# --- Question 2: AES-128 Encryption and Decryption ---
# ==============================================================================
print("--- Question 2: AES-128 ---")
pt2 = b"Sensitive Information"
# AES-128 uses a 16-byte (128-bit) key. We convert the hex string to bytes.
key2_hex = "0123456789ABCDEF0123456789ABCDEF"
key2 = bytes.fromhex(key2_hex)

# Encrypt the message using AES in ECB mode
ct2 = aes_ecb_enc(pt2, key2)
# Decrypt the ciphertext
decrypted_pt2 = aes_ecb_dec(ct2, key2)

print(f"Plaintext: {pt2.decode()}")
print(f"Key (hex): {key2_hex}")
print(f"Ciphertext (hex): {ct2.hex()}")
print(f"Decrypted Text: {decrypted_pt2.decode()}")
print("-" * 25, "\n")


# ==============================================================================
# --- Question 3: Performance Comparison (DES vs. AES-256) ---
# ==============================================================================
print("--- Question 3: Performance Comparison (DES vs. AES-256) ---")
pt3 = b"Performance Testing of Encryption Algorithms"
iterations = 10000

# --- DES Performance ---
des_key = get_random_bytes(8)
start_time = time.perf_counter()
for _ in range(iterations):
    ct = des_enc(pt3, des_key)
end_time = time.perf_counter()
des_enc_time = (end_time - start_time) / iterations

des_ct = des_enc(pt3, des_key)
start_time = time.perf_counter()
for _ in range(iterations):
    pt = des_dec(des_ct, des_key)
end_time = time.perf_counter()
des_dec_time = (end_time - start_time) / iterations

print(f"DES Average Encryption Time: {des_enc_time:.9f} seconds")
print(f"DES Average Decryption Time: {des_dec_time:.9f} seconds")

# --- AES-256 Performance ---
aes_key = get_random_bytes(32) # AES-256 uses a 32-byte key
start_time = time.perf_counter()
for _ in range(iterations):
    ct = aes_ecb_enc(pt3, aes_key)
end_time = time.perf_counter()
aes_enc_time = (end_time - start_time) / iterations

aes_ct = aes_ecb_enc(pt3, aes_key)
start_time = time.perf_counter()
for _ in range(iterations):
    pt = aes_ecb_dec(aes_ct, aes_key)
end_time = time.perf_counter()
aes_dec_time = (end_time - start_time) / iterations

print(f"AES-256 Average Encryption Time: {aes_enc_time:.9f} seconds")
print(f"AES-256 Average Decryption Time: {aes_dec_time:.9f} seconds")
print("\nFinding: AES is generally faster than DES, even with a much larger key size,")
print("due to its modern design optimized for software execution on computers.")
print("-" * 25, "\n")


# ==============================================================================
# --- Question 4: Triple DES (3DES) Encryption and Decryption ---
# ==============================================================================
print("--- Question 4: Triple DES ---")
pt4 = b"Classified Text"
# Triple DES uses a 16 or 24-byte key.
# This key is now valid because the 3 key components are different.
# K1 = 1234567890ABCDEF, K2 = FEDCBA0987654321, K3 = ABCDEF1234567890
key4_hex = "1234567890ABCDEFFEDCBA0987654321ABCDEF1234567890" # <-- THIS LINE IS FIXED
key4 = bytes.fromhex(key4_hex)

# Encrypt the message
ct4 = tdes_enc(pt4, key4)
# Decrypt the ciphertext
decrypted_pt4 = tdes_dec(ct4, key4)

print(f"Plaintext: {pt4.decode()}")
print(f"Key (hex): {key4_hex}")
print(f"Ciphertext (hex): {ct4.hex()}")
print(f"Decrypted Text: {decrypted_pt4.decode()}")
print("-" * 25, "\n")


# ==============================================================================
# --- Question 5: AES-192 Encryption Steps Explanation ---
# ==============================================================================
print("--- Question 5: AES-192 ---")
pt5 = b"Top Secret Data"
# NOTE: The key provided in the question is 16 bytes (128-bit), which is not valid
# for AES-192. AES-192 requires a 24-byte (192-bit) key.
# A valid 24-byte key is used here for the demonstration.
key5_hex = "FEDCBA9876543210FEDCBA98765432100011223344556677"
key5 = bytes.fromhex(key5_hex)

# The high-level functions in helper.py do not expose the internal steps of AES.
# We will perform the encryption and then describe the steps conceptually.
ct5 = aes_ecb_enc(pt5, key5)
decrypted_pt5 = aes_ecb_dec(ct5, key5)

print(f"Plaintext: {pt5.decode()}")
print(f"Key (hex, corrected for 192-bit): {key5_hex}")
print(f"Ciphertext (hex): {ct5.hex()}")
print(f"Decrypted Text: {decrypted_pt5.decode()}")
print("\n--- Conceptual Steps of AES-192 Encryption ---")
print("""
The provided 'helper.py' library (PyCryptodome) is highly optimized and does not
show intermediate values. However, the internal process for AES-192 is as follows:

1.  **Key Expansion**: The original 24-byte (192-bit) key is expanded into a key
    schedule consisting of 13 round keys (each 16 bytes). This process involves
    rotating words, substituting bytes (SubWord), and XORing with a round
    constant (Rcon).

2.  **Initial Round (Round 0)**:
    * **AddRoundKey**: The initial 16-byte plaintext block is XORed with the
      first round key from the key schedule.

3.  **Main Rounds (Rounds 1 to 11 for AES-192)**: AES-192 has 12 rounds in total.
    This loop is repeated 11 times.
    * **SubBytes**: Each byte in the state matrix is replaced with a
      corresponding byte from a fixed lookup table called the S-box. This
      provides non-linearity.
    * **ShiftRows**: The bytes in the last three rows of the state matrix are
      shifted cyclically to the left by different offsets.
    * **MixColumns**: Each column of the state matrix is transformed by
      multiplying it with a fixed polynomial. This provides diffusion.
    * **AddRoundKey**: The current state matrix is XORed with the next
      round key from the schedule.

4.  **Final Round (Round 12)**:
    * **SubBytes**: Same as in the main rounds.
    * **ShiftRows**: Same as in the main rounds.
    * **AddRoundKey**: XOR with the final round key.
    * **Note**: The Final Round is identical to a main round but **omits the
      MixColumns** step.

The final state matrix after these steps is the 16-byte ciphertext block.
""")
print("-" * 25, "\n")
