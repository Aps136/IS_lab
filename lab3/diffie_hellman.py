import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

# Step 1: Agree on public parameters (p and g)
parameters = dh.generate_parameters(generator=2, key_size=2048)
p = parameters.parameter_numbers().p
g = parameters.parameter_numbers().g

print(f"Public Parameters:\nPrime (p): {p}\nGenerator (g): {g}\n")

# --- Alice's Side ---
# Step 2 & 3: Generate private key and public key
start_time_alice = time.time()
private_key_alice = parameters.generate_private_key()
public_key_alice = private_key_alice.public_key()
key_gen_time_alice = time.time() - start_time_alice
print(f"Alice's Key Generation Time: {key_gen_time_alice:.6f} seconds")

# --- Bob's Side ---
# Step 2 & 3: Generate private key and public key
start_time_bob = time.time()
private_key_bob = parameters.generate_private_key()
public_key_bob = private_key_bob.public_key()
key_gen_time_bob = time.time() - start_time_bob
print(f"Bob's Key Generation Time: {key_gen_time_bob:.6f} seconds")

# --- Key Exchange and Shared Secret Computation ---
# Step 4: Exchange public keys (public_key_alice and public_key_bob)
# Step 5: Compute shared secret
start_time_exchange = time.time()

# Alice computes the shared secret
shared_secret_alice = private_key_alice.exchange(public_key_bob)

# Bob computes the shared secret
shared_secret_bob = private_key_bob.exchange(public_key_alice)

key_exchange_time = time.time() - start_time_exchange
print(f"\nKey Exchange & Shared Secret Computation Time: {key_exchange_time:.6f} seconds")

# Verify that both secrets are the same
print(f"\nAlice's shared secret: {shared_secret_alice.hex()[:10]}...")
print(f"Bob's shared secret: {shared_secret_bob.hex()[:10]}...")
print(f"Are the shared secrets equal? {shared_secret_alice == shared_secret_bob}")

# For practical use, the shared secret should be run through a Key Derivation Function (KDF)
# to produce a key for a symmetric algorithm like AES.
# This ensures the final key has the correct length and properties.
derived_key_alice = HKDF(
    algorithm=hashes.SHA256(),
    length=32,  # 32 bytes for an AES-256 key
    salt=None,
    info=b'file-sharing-key'
).derive(shared_secret_alice)

derived_key_bob = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'file-sharing-key'
).derive(shared_secret_bob)

print("\nDerived keys for practical use:")
print(f"Alice's derived key: {derived_key_alice.hex()}")
print(f"Bob's derived key:   {derived_key_bob.hex()}")
