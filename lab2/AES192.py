from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
message=b"Top Secret Data"
key =b"FEDCBA9876543210FEDCBA9876543210"
cipher = AES.new(key, AES.MODE_ECB)
paddedm = pad(message, AES.MODE_ECB)
ciphert =cipher.encrypt(paddedm)

decrypted = cipher.decrypt(ciphert)
origm = unpad(decrypted,AES.block_size)

print("Original Message: ",message.decode())
print("Key :", key.decode())
print("Ciphert: ",ciphert.hex())
print("Decrypted message: ",origm.decode())
