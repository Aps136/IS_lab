from helper import *
n= int(input("Enter number of voters: "))
for i in range(n):
    vote = input("Enter ur vote: ")
    prv, pub = rsa_key()
    print("private key: ",prv)
    print("public key: ", pub)
    manifest = b"VoteManifest2025:CandidateX"
    key16 = b"0123456789ABCDEF"
    print("Original Manifest:", manifest.decode())
    iv = get_random_bytes(16)
    ct = aes_cbc_enc(manifest, key16, iv)
    ctt = rsa_enc(ct, pub)
    print("RSA Enc of AES key:", ctt.hex())
    print("\nAES-CBC Enc:", ct.hex())
    data_bytes = manifest
    hashh=sha256_hash(data_bytes)
    print(f"SHA-256 Hash:{sha256_hash(data_bytes).hex()}")
    signature = rsa_sign(hashh, prv)
    print(f"Generated Signature (first 16 bytes): {signature[:16].hex()}...")
    print("EC is now verifying......")
    is_valid = rsa_verify(hashh, signature, pub)
    print(f"\nVerification with original document: {is_valid}")
    if is_valid:
        print("The signature is authentic.")

    t_manifest = b"VoteManifest2025:CandidateY"
    data_bytes = t_manifest
    hash1 = sha256_hash(data_bytes)
    is_valid = rsa_verify(hash1, signature, pub)
    print(f"\nVerification with original document: {is_valid}")
    if is_valid:
        print("The signature is authentic.")
    else:
        print("Not valid")

