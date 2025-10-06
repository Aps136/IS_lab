from helper import *
records={}
key16 = b"0123456789ABCDEF"
signer_private_key, signer_public_key = rsa_key(2048)
def patient():
    name=input("Enter name: ")
    id=int(input("Enter id: "))
    problem=input("Enter problem: ")
    date=input("Enter date(YYYY-MM-DD): ")
    manifest=f"{name}|{id}|{problem}|{date}"
    manifest_b= manifest.encode()
    #AES ENCRYPTION

    ct = aes_ecb_enc(manifest_b, key16)
    print("\nAES-128 ECB Enc of manifest:", ct.hex())

    h=sha256_hash(manifest_b)

    print("\nOriginal Document:",manifest)
    signature = rsa_sign(h, signer_private_key)
    print(f"Generated Signature (first 16 bytes): {signature[:16].hex()}...")

    records[id]={
        "encrypted":ct,
        "hash":h.hex(),
        "sign":signature,
        "plain": manifest
    }
    print("\nPatient record successfully stored")
def doc():
    id= int(input("Enter patient id to access: "))
    if id not in records:
        print("No such record\n")
        return
    decrypted=aes_ecb_dec(records[id]["encrypted"], key16).decode()
    print("Decrypted record: \n",decrypted)

    hash_d = sha256_hash(decrypted.encode())
    print("Hash of record : ", hash_d.hex())

    is_valid = rsa_verify(hash_d, records[id]["sign"], signer_public_key)
    print(f"\nVerification with original document: {is_valid}")
    if is_valid:
        print("The signature is authentic.")
    else:
        print("Invalid \n")

def auditor():
    if not records:
        return
    for id, data in records.items():
        print(f"\nPatient ID: {id}")
        print(f"Encrypted Data: {data['encrypted'][:60]}...")
        valid = rsa_verify(bytes.fromhex(data["hash"]),data["sign"],signer_public_key)
        print("Signature verification: ", "valid" if valid else "invalid")



def main():
    while True:
        print("1. Patient functions\n")
        print("2. Doctor Functions\n")
        print("3.Auditor Functions\n")
        print("4. Exit\n")
        choice = int(input("Enter your choice: "))
        if choice==4:
            print("Bye\n")
            break
        elif choice==1:
            patient()
        elif choice==2:
            doc()
        elif choice==3:
            auditor()
        else:
            print("Invalid choice\n")
if __name__ == "__main__":
    main()



