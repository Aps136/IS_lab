#pip install pycryptodome
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad 
key = b"A1B2C3D4" #byte string
message = b"Confidential Data"
padded_m = pad(message, 8) #if length not multiple of 8, must be padded
cipher = DES.new(key, DES.MODE_ECB) # each block of code is encrypted independently

ciphert = cipher.encrypt(padded_m)
decrypted_p = cipher.decrypt(ciphert)
orig_m = unpad(decrypted_p,8)  #
print("Original Message: ",message.decode())
print("Ciphertext: ", ciphert.hex())
print("Decrypted message: ",orig_m.decode())
