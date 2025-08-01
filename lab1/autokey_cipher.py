def encode(text, key):
    text = text.replace(" ","").lower()
    ciphertxt=""
    keystream = [key]
    char_to_num ={chr(i+ord('a')): i for i in range(26)}
    num_to_char = {i:chr(i+ord('a')) for i in range(26)}
    for i in range(len(text)):
        pnum = char_to_num[text[i]]
        knum = keystream[i]
        cnum = (pnum +knum)%26
        ciphertxt +=num_to_char[cnum]
        if i+1 <len(text):
            keystream.append(pnum)
    return ciphertxt
def decode(text, key):
    plain=""
    keystream =[key]
    char_to_num = {chr(i + ord('a')): i for i in range(26)}
    num_to_char = {i: chr(i + ord('a')) for i in range(26)}
    for i in range(len(text)):
        cnum = char_to_num[text[i]]
        knum = keystream[i]
        pnum = (cnum - knum +26)%26
        plain+=num_to_char[pnum]
        if i+1<len(text):
            keystream.append(pnum)
    return plain
text ="the house is being sold tonight"
key =7
encrypted = encode(text,key)
decrypted = decode(encrypted,key)
print("After encoding: ", encrypted)
print("After decoding: ",decrypted)
