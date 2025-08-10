from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
message = b"Classified Text"
key = b"1234567890ABCDEF12345678"
cipher = DES3.new(key, DES3.MODE_ECB)
paddedm = pad(message, DES3.block_size)
ciphert = cipher.encrypt(paddedm)
decryptedpadded = cipher.decrypt(ciphert)
origm = unpad(decryptedpadded, DES3.block_size)
print(f"Original Message: {message.decode()}")
print(f"Key: {key.decode()}")
print(f"Ciphertext : {ciphert.hex()}")
print(f"Decrypted Message: {origm.decode()}")
