def genkey(text, key):
    y = len(text)
    repeated=''
    for i in range(y):
        repeated+=key[i%len(key)]
    return repeated

def encode(text, key):
    encoded = ''
    idx =0
    repeated = genkey(text, key)
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            val = ord(char)-shift_base
            kval = ord(repeated[idx].upper())-65
            shifted_val = (val+kval)%26
            encodedchr= chr(shifted_val +shift_base)
            encoded+=encodedchr
            idx+=1
        else:
            encoded+=char
    return encoded
def decode(text, key):
    decoded = ''
    repeated = genkey(text,key)
    idx =0
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            val = ord(char)- shift_base
            kval = ord(repeated[idx].upper())-65
            shiftedval = (val-kval +26)%26
            decodedchr = chr(shiftedval+ shift_base)
            decoded+=decodedchr
            idx+=1
        else:
            decoded+=char
    return decoded

text = "the house is being sold tonight"
key = "dollars"
encoded = encode(text, key)
print(f"Encoded: {encoded}")
decoded = decode(encoded, key)
print(f"Decoded: {decoded}")

