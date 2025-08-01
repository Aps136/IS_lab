def encode(text, key):
    text = text.replace(" ","").lower()
    l = len(key)
    ciphertxt =""
    if len(text)%l !=0:
        text +="x"*(l-(len(text)%l))
    char_to_num ={chr(i+ord('a')):i for i in range(26)}
    num_to_char ={i:chr(i+ord('a')) for i in range(26)}
    for i in range(0,len(text),l):
        block = text[i:i+l]
        txtvector =[char_to_num[char] for char in block]
        ciphert=[]
        for row in range(l):
            rowsum=0
            for col in range(l):
                rowsum+=key[row][col]* txtvector[col]
            ciphert.append(rowsum%26)
        for num in ciphert:
            ciphertxt+=num_to_char[num]
    return ciphertxt
        
text = "We live in an insecure world"
key =[[3,3],[2,7]]
print("original message: ",text)

encryp = encode(text,key)
print("encrypted message: ",encryp)
