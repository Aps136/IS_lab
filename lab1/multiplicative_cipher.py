def encode(text, key):
    encoded=''
    for char in text:
        if  char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encoded += chr(((ord(char)-shift_base)*key)%26 + shift_base)
        else:
            encoded+=char
    return encoded
def decode(text, key):
    decoded =''
    inv= pow(key, -1, 26)
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            decoded += chr(((ord(char)-shift_base)*inv)%26 +shift_base)
        else:
            decoded+=char
    return decoded
text ="I am learning information security"
key = 15
encoded = encode(text,key)
print("after encoding: ", encoded)
decoded = decode(encoded, key)
print("after decoding: ",decoded)
