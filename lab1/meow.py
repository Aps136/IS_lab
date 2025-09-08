import numpy as np

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# --- Helpers ---
def clean(text):
    """Keep only A–Z, uppercase"""
    return "".join(c for c in text.upper() if c.isalpha())

def toZ26(s): return [A.index(c) for c in s]
def fromZ26(v): return "".join(A[i % 26] for i in v)

def modinv(a, m): return pow(int(a), -1, m)

# =====================================================
# Playfair Cipher
# =====================================================
def playfair_key(key):
    k = clean(key).replace("J", "I")
    seen = []
    for ch in (k + A):
        if ch == "J": continue
        if ch not in seen: seen.append(ch)
        if len(seen) == 25: break
    M = [seen[i:i+5] for i in range(0,25,5)]
    pos = {M[r][c]:(r,c) for r in range(5) for c in range(5)}
    return M, pos

def playfair_enc(pt, key):
    M,pos = playfair_key(key)
    p = clean(pt).replace("J","I")
    i = 0; pairs = []
    while i < len(p):
        a = p[i]; b = p[i+1] if i+1 < len(p) else "X"
        if a == b: pairs.append((a,"X")); i += 1
        else: pairs.append((a,b)); i += 2
    out=[]
    for a,b in pairs:
        ra,ca=pos[a]; rb,cb=pos[b]
        if ra==rb: out += [M[ra][(ca+1)%5],M[rb][(cb+1)%5]]
        elif ca==cb: out += [M[(ra+1)%5][ca],M[(rb+1)%5][cb]]
        else: out += [M[ra][cb],M[rb][ca]]
    return "".join(out)

def playfair_dec(ct, key):
    M,pos=playfair_key(key)
    pairs=[clean(ct)[i:i+2] for i in range(0,len(clean(ct)),2)]
    out=[]
    for a,b in pairs:
        ra,ca=pos[a]; rb,cb=pos[b]
        if ra==rb: out += [M[ra][(ca-1)%5],M[rb][(cb-1)%5]]
        elif ca==cb: out += [M[(ra-1)%5][ca],M[(rb-1)%5][cb]]
        else: out += [M[ra][cb],M[rb][ca]]
    return "".join(out)

# =====================================================
# Vigenere Cipher
# =====================================================
def vig_enc(pt, key):
    p = clean(pt); k = clean(key)
    return fromZ26([(pi + toZ26(k[i % len(k)])[0]) % 26
                    for i, pi in enumerate(toZ26(p))])

def vig_dec(ct, key):
    c = clean(ct); k = clean(key)
    return fromZ26([(ci - toZ26(k[i % len(k)])[0]) % 26
                    for i, ci in enumerate(toZ26(c))])

# =====================================================
# Autokey Cipher
# =====================================================
def autokey_enc(pt, key):
    p = clean(pt); k = clean(key)
    s = toZ26(k + p)
    return fromZ26([(pi + s[i]) % 26 for i, pi in enumerate(toZ26(p))])

def autokey_dec(ct, key):
    c = toZ26(clean(ct)); k = toZ26(clean(key)); out = []
    for i, ci in enumerate(c):
        ki = k[i] if i < len(k) else out[i - len(k)]
        out.append((ci - ki) % 26)
    return fromZ26(out)

# =====================================================
# Hill Cipher (n×n general)
# =====================================================
def hill_enc(pt, K):
    n = K.shape[0]
    p = clean(pt)
    while len(p) % n != 0: p += "X"   # pad with X
    nums = toZ26(p)
    out=[]
    for i in range(0,len(nums),n):
        block = np.array(nums[i:i+n])
        enc_block = K.dot(block) % 26
        out.extend(enc_block)
    return fromZ26(out)

def hill_dec(ct, K):
    n = K.shape[0]
    nums = toZ26(clean(ct))
    det = int(round(np.linalg.det(K))) % 26
    inv_det = modinv(det, 26)

    # adjugate matrix mod 26
    K_inv = inv_det * np.round(det * np.linalg.inv(K)).astype(int)
    K_inv = K_inv % 26

    out=[]
    for i in range(0,len(nums),n):
        block = np.array(nums[i:i+n])
        dec_block = K_inv.dot(block) % 26
        out.extend(dec_block)
    return fromZ26(out)

# =====================================================
# DEMO
# =====================================================
if __name__ == "__main__":
    print("=== Playfair ===")
    ct = playfair_enc("HIDETHEGOLDINTHETREE", "MONARCHY")
    print("Enc:", ct)
    print("Dec:", playfair_dec(ct, "MONARCHY"))

    print("\n=== Vigenere ===")
    ct = vig_enc("HELLO WORLD", "KEY")
    print("Enc:", ct)
    print("Dec:", vig_dec(ct, "KEY"))

    print("\n=== Autokey ===")
    ct = autokey_enc("HELLO WORLD", "K")
    print("Enc:", ct)
    print("Dec:", autokey_dec(ct, "K"))

    print("\n=== Hill (3x3) ===")
    K = np.array([[6,24,1],[13,16,10],[20,17,15]]) # invertible mod 26
    ct = hill_enc("ACT", K)
    print("Enc:", ct)
    print("Dec:", hill_dec(ct, K))
