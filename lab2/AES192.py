from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
message = b"Top Secret Data"
# A valid 24-byte (192-bit) key for AES-192
key = b"0123456789abcdef01234567"
cipher = AES.new(key, AES.MODE_ECB)
paddedm = pad(message, AES.block_size)
ciphert = cipher.encrypt(paddedm)
decryptedpad = cipher.decrypt(ciphert)
origm = unpad(decryptedpad, AES.block_size)
print(f"Original Message: {origm.decode()}")
print(f"Key: {key.hex()}")
print(f"CipherText: {ciphert.hex()}")
print(f"Decrypted Message: {origm.decode()}")
