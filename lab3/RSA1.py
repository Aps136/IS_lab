def encrypt(message, e,n):
    cipher = [pow(ord(char),e,n) for char in message]
    return cipher
def decrypt(cipher, d,n):
    message = ''.join([chr(pow(char, d,n)) for char in cipher])
    return message
n = 3233
e =17
d= 2753
message ='Assymetric Encryption'
print('Original message: ',message)
ciphert = encrypt(message, e,n)
print("ENcrypted CIphertext: ",ciphert)
decryptedm = decrypt(ciphert, d,n)
print("Decrypted message: ",decryptedm)
