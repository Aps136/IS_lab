from helper import *
key16=b"0123456789ABCDEF"
signer_private_key, signer_public_key = rsa_key(2048)
from Crypto.Random import get_random_bytes

def sender():
    message=input("Enter your message: ")
    iv = get_random_bytes(16)
    message_b = message.encode()
    ct = aes_cbc_enc(message_b, key16, iv)
    print("\nAES-CBC Enc:", ct.hex())

    with open('f.txt', 'w') as f:
        f.write(ct.hex())
    with open('iv.txt', 'w') as f:
        f.write(iv.hex())
    print("Successfully written to file\n")
    hash=sha256_hash(message_b)
    signature = rsa_sign(hash, signer_private_key)
    with open('sign.txt', 'wb') as f:
        f.write(signature)
    print("sending files to recver")
def rec():
    with open('f.txt', 'r') as f:
        ct_hex = f.read().strip()
    with open('iv.txt', 'r') as f:
        iv_hex = f.read().strip()
    with open('sign.txt', 'rb') as f:
        signature = f.read()
    ct= bytes.fromhex(ct_hex)
    iv = bytes.fromhex(iv_hex)
    decrypted = aes_cbc_dec(ct,key16, iv)
    print(decrypted.decode())
    h_recv= sha256_hash(decrypted)
    valid = rsa_verify(h_recv, signature, signer_public_key)
    print("\nSignature verification:", "VALID ✅" if valid else "INVALID ❌")


def auditor():
    with open('f.txt', 'r') as f:
        ct_hex = f.read().strip()
    print("encrypted message: ", ct_hex[:60],"...")
    with open('sign.txt','rb') as f:
        signature = f.read()
    print("auditor cannot decrypt \n")



def main():
    while True:
        print("1. Sender Operations")
        print("2. Recveiver Operations")
        print("3. Auditor Operations")
        print("4. Exit")
        choice = int(input("Enter your choice: "))
        if(choice==4):
            break;
        elif choice==1:
            sender()
        elif choice==2:
            rec()
        elif choice==3:
            auditor()
        else:
            print("Invalid choice")
if __name__ == "__main__":
    main()
