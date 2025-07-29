def gene(key):
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = key.upper().replace('J', 'I')
    m = [['' for _ in range(5)] for _ in range(5)]
    sets = set()
    row, col = 0, 0

    for char in key:
        if char not in sets and char.isalpha():
            m[row][col] = char
            sets.add(char)
            col += 1
            if col == 5:
                col = 0
                row += 1

    for char in alpha: 
        if char not in sets:
            m[row][col] = char
            sets.add(char)
            col += 1
            if col == 5:
                col = 0
                row += 1
    return m

def prepare(ptext):
    ptext = ptext.upper().replace('J', 'I')
    newtxt = ""
    i = 0
    while i < len(ptext):
        char1 = ptext[i]
        if not char1.isalpha():
            i += 1
            continue

        if i + 1 < len(ptext):
            char2 = ptext[i+1]
            if not char2.isalpha(): 
                newtxt += char1 + 'X'
                i += 1
                continue

            if char1 == char2:
                newtxt += char1 + 'X'
                i += 1
            else:
                newtxt += char1 + char2
                i += 2
        else:
            newtxt += char1 + 'X'
            i += 1
    return newtxt

def find(m, char):
    for r in range(5):
        for j in range(5):
            if m[r][j] == char:
                return r, j
    return -1, -1

def encrypt_digraph(m, digraph):
    r1, c1 = find(m, digraph[0])
    r2, c2 = find(m, digraph[1])

    if r1 == r2:
        return m[r1][(c1 + 1) % 5] + m[r2][(c2 + 1) % 5]
    elif c1 == c2:
        return m[(r1 + 1) % 5][c1] + m[(r2 + 1) % 5][c2]
    else:
        return m[r1][c2] + m[r2][c1]

def decrypt_digraph(m, digraph):
    r1, c1 = find(m, digraph[0])
    r2, c2 = find(m, digraph[1])

    if r1 == r2:
        return m[r1][(c1 - 1 + 5) % 5] + m[r2][(c2 - 1 + 5) % 5]
    elif c1 == c2:
        return m[(r1 - 1 + 5) % 5][c1] + m[(r2 - 1 + 5) % 5][c2]
    else:
        return m[r1][c2] + m[r2][c1]

def encrypt(ptext, key):
    matrix = gene(key)
    prepared_text = prepare(ptext)
    
    ctext = ""
    for i in range(0, len(prepared_text), 2):
        digraph = prepared_text[i:i+2]
        ctext += encrypt_digraph(matrix, digraph)
    return ctext

def decrypt(ctext, key):
    matrix = gene(key)
    
    dtext = ""
    for i in range(0, len(ctext), 2):
        digraph = ctext[i:i+2]
        dtext += decrypt_digraph(matrix, digraph)
    
    final_dtext = ""
    i = 0
    while i < len(dtext):
        if i + 1 < len(dtext) and dtext[i+1] == 'X':
            if i + 2 < len(dtext) and dtext[i] == dtext[i+2]:
                final_dtext += dtext[i]
                i += 2 
            elif i == len(dtext) - 2 and dtext[i+1] == 'X':
                final_dtext += dtext[i]
                i += 2
            else:
                final_dtext += dtext[i]
                final_dtext += dtext[i+1]
                i += 2
        else:
            final_dtext += dtext[i]
            i += 1
            
    return final_dtext.replace('X', '') 

text = "The key is hidden under the door pad"
key = "GUIDANCE"

encrypted_text = encrypt(text, key)
print(f"Original Text: {text}")
print(f"Encrypted Text: {encrypted_text}")

decrypted_text = decrypt(encrypted_text, key)
print(f"Decrypted Text: {decrypted_text}")
