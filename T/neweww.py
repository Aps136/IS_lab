from helper import *
key = [[3, 3], [2, 7]]
key16 = b"0123456789ABCDEF"
signer_private_key, signer_public_key = rsa_key(2048)
records = {}
def patient():
    name=input("Enter name: ")
    id=int(input("Enter id: "))
    problem=input("Enter problem: ")
    date=input("Enter date(YYYY-MM-DD): ")
    manifest=f"{name}|{id}|{problem}|{date}"
    manifest_b= manifest.encode()
    #HILL ENCRYPTION

    v = hill_all(manifest, key)
    ct_hill = v.encrypt()
    hill_b =ct_hill.encode()
    print("after hill cipher : ", hill_b)
    print("+============")
    #pt = v.decrypt(ct)
    #print(ct, pt, sep='\n')
    #print('-' * 100)

    #AES
    ct_aes = aes_ecb_enc(hill_b, key16)
    print("\nAES-128 ECB Enc of manifest:", ct_aes.hex())
    print("------------")
    h=sha256_hash(ct_aes)
    print("After hashing: ",h)
    print("--------------------")
    print("\nOriginal Document:",manifest)
    signature = rsa_sign(h, signer_private_key)
    print(f"Generated Signature (first 16 bytes): {signature[:16].hex()}...")
    records[id] = {
        "hill": ct_hill,
        "aes": ct_aes,
        "hash": h,
        "sign": signature,
        "v": v
    }
    print("\n✅ Patient record successfully stored.\n")
def doc():
    id = int(input("enter id: "))
    rec = records[id]
    ct_aes = rec["aes"]
    signature = rec["sign"]
    hash_d = sha256_hash(ct_aes)
    print("Hash of record : ", hash_d.hex())

    is_valid = rsa_verify(hash_d, signature, signer_public_key)
    print(f"\nVerification with original document: {is_valid}")
    if is_valid:
        print("The signature is authentic.")
    else:
        print("Invalid \n")
    decrypted = aes_ecb_dec(ct_aes, key16).decode()
    print("Decrypted record: \n", decrypted)
    pt= rec["v"].decrypt(decrypted)
    print("pt: ",pt)


def main():
    while True:
        print("1. Patient functions\n")
        print("2. Doctor Functions\n")
        print("3. Exit\n")
        choice = int(input("Enter your choice: "))
        if choice==4:
            print("Bye\n")
            break
        elif choice==1:
            patient()
        elif choice==2:
            doc()
        else:
            print("Invalid choice\n")
if __name__ == "__main__":
    main()
