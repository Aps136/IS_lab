import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# Step 1: Public parameters (known to both)
p = 23          # a prime number
g = 5           # primitive root modulo p

print("Publicly shared values:")
print(f"Prime (p) = {p}, Generator (g) = {g}")

# Step 2: Alice chooses private key a
a = random.randint(2, p-2)
A = pow(g, a, p)   # Alice's public value

# Step 3: Bob chooses private key b
b = random.randint(2, p-2)
B = pow(g, b, p)   # Bob's public value

print("\nKey Exchange:")
print(f"Alice sends A = {A}")
print(f"Bob sends B = {B}")

# Step 4: Both compute shared secret
alice_shared = pow(B, a, p)
bob_shared = pow(A, b, p)

print("\nShared Secret Computed:")
print(f"Alice's secret = {alice_shared}")
print(f"Bob's secret = {bob_shared}")

# Both should be same
assert alice_shared == bob_shared
shared_secret = alice_shared

# Step 5: Derive AES key from shared secret (hash it to 16 bytes for AES-128)
aes_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]

print(f"\nAES-128 key derived = {aes_key.hex()}")

# Step 6: Encrypt and decrypt a message using the derived AES key
message = b"Hello Diffie-Hellman Secure World!"
cipher = AES.new(aes_key, AES.MODE_CBC)   # CBC mode with random IV
ct_bytes = cipher.encrypt(pad(message, AES.block_size))

iv = cipher.iv
print(f"\nEncrypted (hex) = {ct_bytes.hex()}")

# Decrypt
cipher_dec = AES.new(aes_key, AES.MODE_CBC, iv)
decrypted = unpad(cipher_dec.decrypt(ct_bytes), AES.block_size)

print(f"Decrypted = {decrypted.decode()}")
