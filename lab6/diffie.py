from Crypto.Util.number import getPrime
from random import randint

def generate_dh_keypair(p, g, fixed_private_key):
    private_key = fixed_private_key
    public_key = pow(g, private_key, p)
    return private_key, public_key

def sign(private_key, other_public_key, p):
    return pow(other_public_key, private_key, p)

def verify(private_key, other_public_key, shared_secret, p):
    return sign(private_key, other_public_key, p) == shared_secret

p = 115
g = 2

FIXED_PRIVATE_KEY_A = 7
FIXED_PRIVATE_KEY_B = 11

private_key_A, public_key_A = generate_dh_keypair(p, g, FIXED_PRIVATE_KEY_A)

private_key_B, public_key_B = generate_dh_keypair(p, g, FIXED_PRIVATE_KEY_B)

shared_secret_A = sign(private_key_A, public_key_B, p)

shared_secret_B = sign(private_key_B, public_key_A, p)

is_valid = verify(private_key_B, public_key_A, shared_secret_A, p)

print(f"Fixed Private Key A: {private_key_A}")
print(f"Public Key A (2^7 mod 115): {public_key_A}")
print(f"Fixed Private Key B: {private_key_B}")
print(f"Public Key B (2^11 mod 115): {public_key_B}")
print("-" * 30)
print(f"Shared Secret A ((B_pub)^A): {shared_secret_A}")
print(f"Shared Secret B ((A_pub)^B): {shared_secret_B}")
print("-" * 30)
print("Diffie-Hellman Signature valid:", is_valid)
