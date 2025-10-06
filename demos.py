from helper import *

#------------------------------
#------------------------------
# --main-----------------------
#------------------------------
#------------------------------

msg="HELLOWORLD"


# Transposition
ct=transpose_enc(msg,5)
print("\nTranspose Enc:",ct)
print("Transpose Dec:",transpose_dec(ct,5))

print("\n:Symmetric Ciphers ===")

# DES
key8=b"A1B2C3D4"
ct=des_enc(b"SecretMsg",key8)
print("DES Enc:",ct.hex())
pt = des_dec(ct,key8)
print("DES Dec:",pt.decode())

# 3DES
key24=DES3.adjust_key_parity(get_random_bytes(24))
ct=tdes_enc(b"Classified",key24)
print("\n3DES Enc:",ct.hex())
print("3DES Dec:",tdes_dec(ct,key24).decode())

# AES-128 ECB
key16=b"0123456789ABCDEF"
ct=aes_ecb_enc(b"SensitiveData",key16)
print("\nAES-128 ECB Enc:",ct.hex())
print("AES-128 ECB Dec:",aes_ecb_dec(ct,key16).decode())

# AES-CBC
iv=get_random_bytes(16)
ct=aes_cbc_enc(b"TopSecretInfo",key16,iv)
print("\nAES-CBC Enc:",ct.hex())
print("AES-CBC Dec:",aes_cbc_dec(ct,key16,iv).decode())

# AES-CTR
nonce=get_random_bytes(8)
ct=aes_ctr_enc(b"CounterMode",key16,nonce)
print("\nAES-CTR Enc:",ct.hex())
print("AES-CTR Dec:",aes_ctr_dec(ct,key16,nonce).decode())



print("\n: Asymmetric Ciphers ===")

# RSA
prv,pub=rsa_key()
ct=rsa_enc(b"Asymmetric Encryption",pub)
print("RSA Enc:",ct.hex())
print("RSA Dec:",rsa_dec(ct,prv).decode())

# ElGamal
P,G,H,X=elg_key()
m=34534
c1,c2=elg_enc(m,P,G,H)
print("\nElGamal Enc:",(c1,c2))
print("ElGamal Dec:",elg_dec(c1,c2,P,X))

#encryption of elgamal for string messages
message = [ord(i) for i in 'message']
c1s = []
c2s = []
ps,gs,hs,xs = [],[],[],[]
for m in message:
    P, G, H, X = elg_key()
    ps.append(P)
    gs.append(G)
    hs.append(H)
    xs.append(X)
    c1, c2 = elg_enc(m, P, G, H)
    c1s.append(c1)
    c2s.append(c2)
print(c1s,c2s,sep = '\n')
#decryption of elgamal for string messages
message = []
for i,j,k,l in zip(c1s,c2s,ps,xs):
    pc = elg_dec(i,j,k,l)
    message.append(pc)
print("".join([chr(i) for i in message]))


# Diffie-Hellman
p,g=dh_params(); a,A=dh_keypair(p,g); b,B=dh_keypair(p,g)
print("\nDH Shared Secret (both sides):",dh_shared(p,a,B),dh_shared(p,b,A),sep = '\n')

# ECC ECIES
ecc=ECC.generate(curve='P-256')
eph,iv,ct,tag=ecies_enc(b"ECC secure message",ecc)
print("\nECC Enc (ciphertext shown):",ct.hex())
print("ECC Dec:",ecies_dec(eph,iv,ct,tag,ecc).decode())


#rabin
n,p,q=rabin_key()
m=int.from_bytes(b"Hi","big")
c=rabin_enc(m,n)
roots=rabin_dec(c,n,p,q)
print("Rabin Enc:",c)
print("Rabin Dec candidates:")
[print(i) for i in [r.to_bytes((r.bit_length()+7)//8,'big') for r in roots]]

print("\n" + "=" * 20 + " LAB 5: HASHING " + "=" * 20)

# ---  Main Execution Block for Labs 5 & 6 ---
# 1. Custom DJB2 Hash
test_string = "This is a test for data integrity."
custom_hash = djb2_hash(test_string)
print(f"DJB2 Hash for '{test_string}': {custom_hash}")

# 2. Standard Hashes Comparison
data_bytes = b"Hello World for Hashing"
print(f"\nMD5 Hash:    {md5_hash(data_bytes).hex()}")
print(f"SHA-1 Hash:  {sha1_hash(data_bytes).hex()}")
print(f"SHA-256 Hash:{sha256_hash(data_bytes).hex()}")

print("\n" + "=" * 20 + " LAB 6: DIGITAL SIGNATURES " + "=" * 20)

# Generate a key pair for signing
signer_private_key, signer_public_key = rsa_key(2048)

# 1. Sign a document
document = b"This document is authentic and has not been tampered with."
print(f"\nOriginal Document: {document.decode()}")

signature = rsa_sign(document, signer_private_key)
print(f"Generated Signature (first 16 bytes): {signature[:16].hex()}...")

# 2. Verify the signature (Authentic case)
is_valid = rsa_verify(document, signature, signer_public_key)
print(f"\nVerification with original document: {is_valid}")
if is_valid:
    print("The signature is authentic.")

# 3. Tamper with the document and try to verify again
tampered_document = b"This document has been TAMPERED with."
is_tampered_valid = rsa_verify(tampered_document, signature, signer_public_key)
print(f"\nVerification with tampered document: {is_tampered_valid}")
if not is_tampered_valid:
    print("The signature was correctly identified as INVALID for the tampered document.")


print("--- Schnorr Digital Signature Demonstration ---")

# 1. Setup: Generate public parameters
p, q, g = generate_schnorr_params()
print("\n1. Public Parameter Generation:")
print(f"  - Prime (p): {p}")
print(f"  - Order (q): {q}")
print(f"  - Generator (g): {g}")

    # 2. Key Generation
x, y = schnorr_keygen(p, q, g)
print("\n2. Key Generation:")
print(f"  - Public Key (y): {y}")
print(f"  - Private Key (x): [SECRET]")

    # 3. Signing
message = b"This message needs to be signed for authenticity."
signature = schnorr_sign(message, p, q, g, x)
print("\n3. Signing:")
print(f"  - Message: {message.decode()}")
print(f"  - Signature (r, s): {signature}")

    # 4. Verification
is_valid = schnorr_verify(message, signature, p, g, y)
print("\n4. Verification:")
if is_valid:
    print("✅ SUCCESS: The signature is valid. Message is authentic and unmodified.")
else:
    print("❌ FAILED: The signature is invalid.")

# 5. Tampering Demonstration
tampered_message = b"This message has been TAMPERED with."
is_tampered_valid = schnorr_verify(tampered_message, signature, p, g, y)
print("\n5. Verification with Tampered Message:")
print(f"  - Tampered Message: {tampered_message.decode()}")
if not is_tampered_valid:
    print("✅ SUCCESS: The invalid signature correctly detected the message tampering.")
else:
    print("❌ FAILED: The signature should have been invalid.")



#diffe helmand

# --- 1. Public Agreement ---
# Alice and Bob publicly agree on the prime 'p' and generator 'g'.
# These can be transmitted over an insecure channel.
prime_bits = 256
p, g = generate_dh_params(prime_bits)
print(f"--- Public Parameters ---")
print(f"Prime (p): {p}")
print(f"Generator (g): {g}\n")


# --- 2. Alice's Side ---
# Alice generates her own secret private key and a public key to share.
private_key_alice, public_key_alice = generate_keypair(p, g)
print(f"--- Alice's Keys ---")
print(f"Alice's Private Key (secret): {private_key_alice}")
print(f"Alice's Public Key (to send to Bob): {public_key_alice}\n")


# --- 3. Bob's Side ---
# Bob does the same, generating his own secret private key and a public key.
private_key_bob, public_key_bob = generate_keypair(p, g)
print(f"--- Bob's Keys ---")
print(f"Bob's Private Key (secret): {private_key_bob}")
print(f"Bob's Public Key (to send to Alice): {public_key_bob}\n")


# --- 4. The Exchange ---
# Alice sends her public key to Bob.
# Bob sends his public key to Alice.
# An eavesdropper might see these public keys, but that's okay.
print(f"--- The Key Exchange ---")
print("Alice sends her public key to Bob.")
print("Bob sends his public key to Alice.\n")


# --- 5. Shared Secret Calculation ---
# Alice uses her private key and Bob's public key to calculate the shared secret.
shared_secret_alice = calculate_shared_secret(public_key_bob, private_key_alice, p)

# Bob uses his private key and Alice's public key to calculate the shared secret.
shared_secret_bob = calculate_shared_secret(public_key_alice, private_key_bob, p)


# --- 6. Verification ---
print(f"--- Shared Secret ---")
print(f"Alice's calculated secret: {shared_secret_alice}")
print(f"Bob's calculated secret:   {shared_secret_bob}\n")

if shared_secret_alice == shared_secret_bob:
    print("✅ Success! Alice and Bob have established the same shared secret.")
    print("They can now use this secret to encrypt their communications.")
else:
    print("❌ Error! The secrets do not match.")


#elgamal digital signature

# 1. Define the original message
original_message = b"This is a secret message for demonstration."
print(f"Original Message: {original_message.decode()}")
print("-" * 20)

# 2. Generate ElGamal keys
public_key, private_key = elgamal_keygen()
print("ElGamal keys generated successfully.")

# 3. Create a hash of the message
message_hash = hashlib.sha256(original_message).digest()
print(f"Message Hash: {message_hash.hex()}")

# 4. Sign the hash with the private key
signature = elgamal_sign(message_hash, private_key)
print(f"Generated Signature (r, s): {signature}")
print("-" * 20)

# 5. Verify the signature with the public key (SUCCESS CASE)
is_valid = elgamal_verify(message_hash, signature, public_key)
print(f"✅ Verification with original data is successful: {is_valid}")
print("-" * 20)

# 6. Attempt to verify with tampered data (FAILURE CASE)
tampered_message = b"This is a tampered message."
tampered_hash = hashlib.sha256(tampered_message).digest()

print(f"Tampered Message: {tampered_message.decode()}")
is_valid_tampered = elgamal_verify(tampered_hash, signature, public_key)
print(f"❌ Verification with tampered data fails as expected: {is_valid_tampered}")






