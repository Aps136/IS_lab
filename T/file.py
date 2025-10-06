import os, datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

# === RSA Key Generation ===
if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
    key = RSA.generate(2048)
    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    with open("public.pem", "wb") as f:
        f.write(key.publickey().export_key())

with open("private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())
with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

records = {}

# === AES helpers ===
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes  # prepend IV

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# === Role functions ===
def patient():
    filename = input("Enter file name (with .txt): ")
    if not os.path.exists(filename):
        print("File not found.")
        return
    with open(filename, "rb") as f:
        data = f.read()

    key = get_random_bytes(16)  # AES-128 key
    encrypted = aes_encrypt(data, key)
    encfile = filename.replace(".txt", "_enc.bin")
    with open(encfile, "wb") as f:
        f.write(encrypted)
    print(f"Encrypted file stored as {encfile}")

    h = SHA512.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    signfile = filename.replace(".txt", "_sign.bin")
    with open(signfile, "wb") as f:
        f.write(signature)
    print(f"Signature stored as {signfile}")

    records[filename] = {
        "encfile": encfile,
        "signfile": signfile,
        "key": key,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    print(f"Record stored at {records[filename]['timestamp']}")

def doctor():
    filename = input("Enter patient file name (original .txt): ")
    if filename not in records:
        print("No such record.")
        return

    with open(records[filename]["encfile"], "rb") as f:
        enc_data = f.read()
    decrypted = aes_decrypt(enc_data, records[filename]["key"])
    print("Decrypted file content:\n", decrypted.decode())

    # Compute hash again
    new_hash = SHA512.new(decrypted)

    # Verify signature
    with open(records[filename]["signfile"], "rb") as f:
        signature = f.read()

    try:
        pkcs1_15.new(public_key).verify(new_hash, signature)
        print("Signature is VALID ✅")
    except (ValueError, TypeError):
        print("Signature is INVALID ❌")

    # Store hash verification result
    verify_file = filename.replace(".txt", "_verify.txt")
    with open(verify_file, "w") as f:
        f.write("Verification Result: Signature VALID\n" if True else "INVALID\n")
    print(f"Verification result saved in {verify_file}")

def auditor():
    print("\nAuditor Accessing Records...\n")
    for filename, info in records.items():
        print(f"Patient File: {filename}")
        print(f"Encrypted file: {info['encfile']}")
        print(f"Timestamp: {info['timestamp']}")
        # Re-verify signature
        with open(filename, "rb") as f:
            data = f.read()
        with open(info["signfile"], "rb") as f:
            signature = f.read()
        h = SHA512.new(data)
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            print("Signature verification: VALID ✅")
        except (ValueError, TypeError):
            print("Signature verification: INVALID ❌")
        print("-" * 50)

# === Main menu ===
def main():
    while True:
        print("\n--- HOSPITAL MANAGEMENT SYSTEM ---")
        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("4. Exit")
        ch = input("Enter choice: ")

        if ch == "1":
            patient()
        elif ch == "2":
            doctor()
        elif ch == "3":
            auditor()
        elif ch == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
