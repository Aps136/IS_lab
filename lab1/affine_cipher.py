def encode(text, a,b):
    encoded=''
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encoded+= chr(((a*(ord(char)-shift_base)+b)%26)+shift_base)
        else:
            encoded+=char
    return encoded
def decode(text, a,b):
    decoded = ''
    inv = pow(a,-1,26)
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            decoded += chr(((inv*((ord(char)-shift_base)-b))%26)+shift_base)
        else:
            decoded += char
    return decoded
text ="I am learning information security"
a=15
b=20
encoded = encode(text,a,b)
print("After Encoding:", encoded)
decoded= decode(encoded,a,b)
print("After Decoding: ", decoded)
