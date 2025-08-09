from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
key_hex ="0123456789ABCDEF0123456789ABCDEF"
key =bytes.fromhex(key_hex)
message =b"Sensitive Information"
paddedm = pad(message, AES.block_size)
cipher = AES.new(key,AES.MODE_ECB)
ciphert = cipher.encrypt(paddedm)
decryptedp = cipher.decrypt(ciphert)
orig = unpad(decryptedp, AES.block_size)
print(f"Original: {message.decode()}")
print(f"key: {key.hex()} ")
print(f"Cipher text: {ciphert.hex()}")
print(f"Decrypted Message: {orig.decode()}")
