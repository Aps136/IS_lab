import math, random, time
from Crypto.Cipher import DES, DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

# =====================================================
# HELPER FUNCTIONS
# =====================================================

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# --- text cleaning / conversions ---
clean   = lambda s: "".join(c for c in s.upper() if c.isalpha())
toZ26   = lambda s: [A.index(c) for c in s]
fromZ26 = lambda v: "".join(A[i % 26] for i in v)

# modular inverse (requires Python 3.8+)
def modinv(a, m):
    return pow(int(a), -1, m)

# PKCS7 padding for block ciphers
def pad(b: bytes, bs: int) -> bytes:
    p = bs - (len(b) % bs)
    return b + bytes([p]) * p

def unpad(b: bytes) -> bytes:
    if not b: return b
    p = b[-1]
    return b[:-p]

# =====================================================
# LAB 1: CLASSICAL CIPHERS
# =====================================================

# --- Caesar ---
def caesar_enc(pt, k): return fromZ26([(x + k) % 26 for x in toZ26(clean(pt))])
def caesar_dec(ct, k): return fromZ26([(x - k) % 26 for x in toZ26(clean(ct))])

# --- Multiplicative ---
def mult_enc(pt, k): return fromZ26([(x * k) % 26 for x in toZ26(clean(pt))])
def mult_dec(ct, k):
    try:
        inv = modinv(k, 26)
    except ValueError:
        raise ValueError("Key not invertible modulo 26")
    return fromZ26([(x * inv) % 26 for x in toZ26(clean(ct))])

# --- Affine ---
def affine_enc(pt, a, b): return fromZ26([(a * x + b) % 26 for x in toZ26(clean(pt))])
def affine_dec(ct, a, b):
    try:
        ai = modinv(a, 26)
    except ValueError:
        raise ValueError("Multiplicative key 'a' not invertible modulo 26")
    return fromZ26([(ai * (x - b)) % 26 for x in toZ26(clean(ct))])

# --- Vigenere ---
def vig_enc(pt, key):
    p = clean(pt); k = clean(key)
    if not k: return ""
    return fromZ26([(p_i + toZ26(k[i % len(k)])[0]) % 26 for i, p_i in enumerate(toZ26(p))])
def vig_dec(ct, key):
    c = clean(ct); k = clean(key)
    if not k: return ""
    return fromZ26([(c_i - toZ26(k[i % len(k)])[0]) % 26 for i, c_i in enumerate(toZ26(c))])

# --- Autokey ---
def autokey_enc(pt, key):
    p = clean(pt); k = clean(key)
    s = toZ26(k + p)
    return fromZ26([(p_i + s[i]) % 26 for i, p_i in enumerate(toZ26(p))])
def autokey_dec(ct, key):
    c = toZ26(clean(ct)); k = toZ26(clean(key)); out = []
    for i, ci in enumerate(c):
        ki = k[i] if i < len(k) else out[i - len(k)]
        out.append((ci - ki) % 26)
    return fromZ26(out)

# --- Playfair ---
def playfair_key(key):
    k = clean(key).replace("J", "I")
    seen = []
    for ch in (k + A):
        if ch == "J": continue
        if ch not in seen:
            seen.append(ch)
        if len(seen) == 25: break
    M = [seen[i:i+5] for i in range(0,25,5)]
    pos = {M[r][c]:(r,c) for r in range(5) for c in range(5)}
    return M,pos

def playfair_enc(pt,key):
    M,pos=playfair_key(key); p=clean(pt).replace("J","I")
    # form digrams
    i=0; pairs=[]
    while i < len(p):
        a=p[i]; b=p[i+1] if i+1<len(p) else "X"
        if a==b: pairs.append((a,"X")); i+=1
        else: pairs.append((a,b)); i+=2
    out=[]
    for a,b in pairs:
        ra,ca=pos[a]; rb,cb=pos[b]
        if ra==rb: out.extend([M[ra][(ca+1)%5],M[rb][(cb+1)%5]])
        elif ca==cb: out.extend([M[(ra+1)%5][ca],M[(rb+1)%5][cb]])
        else: out.extend([M[ra][cb],M[rb][ca]])
    return "".join(out)

def playfair_dec(ct,key):
    M,pos=playfair_key(key); pairs=[clean(ct)[i:i+2] for i in range(0,len(clean(ct)),2)]
    out=[]
    for a,b in pairs:
        ra,ca=pos[a]; rb,cb=pos[b]
        if ra==rb: out.extend([M[ra][(ca-1)%5],M[rb][(cb-1)%5]])
        elif ca==cb: out.extend([M[(ra-1)%5][ca],M[(rb-1)%5][cb]])
        else: out.extend([M[ra][cb],M[rb][ca]])
    return "".join(out)

# --- Hill (2x2 support kept for legacy) ---
def hill_enc(pt,K):
    p=clean(pt)
    if len(p)%2: p+="X"
    nums=toZ26(p)
    out=[]
    # support both tuple/list of 4 and 2x2 matrix-like
    if isinstance(K, (tuple, list)) and len(K)==4:
        a,b,c,d=K
    else:
        a,b,c,d = K[0][0], K[0][1], K[1][0], K[1][1]
    for i in range(0,len(nums),2):
        x,y=nums[i],nums[i+1]
        out+=[(a*x+b*y)%26,(c*x+d*y)%26]
    return fromZ26(out)

def hill_dec(ct,K):
    nums=toZ26(clean(ct))
    if isinstance(K, (tuple, list)) and len(K)==4:
        a,b,c,d=K
    else:
        a,b,c,d = K[0][0], K[0][1], K[1][0], K[1][1]
    det=(a*d-b*c)%26
    try:
        inv=modinv(det,26)
    except ValueError:
        raise ValueError("Hill key matrix not invertible modulo 26")
    ai,bi,ci,di=(d*inv)%26,((-b)*inv)%26,((-c)*inv)%26,(a*inv)%26
    out=[]
    for i in range(0,len(nums),2):
        x,y=nums[i],nums[i+1]
        out+=[(ai*x+bi*y)%26,(ci*x+di*y)%26]
    return fromZ26(out)

# --- Transposition ---
def transpose_enc(pt,cols):
    p=clean(pt); rows=math.ceil(len(p)/cols)
    grid=[p[i*cols:(i+1)*cols].ljust(cols,"X") for i in range(rows)]
    return "".join("".join(r[c] for r in grid) for c in range(cols))
def transpose_dec(ct,cols):
    ctext=clean(ct); rows=math.ceil(len(ctext)/cols)
    it=iter(ctext); grid=[[""]*cols for _ in range(rows)]
    for c in range(cols):
        for r in range(rows): grid[r][c]=next(it)
    return "".join("".join(r) for r in grid).rstrip("X")

# =====================================================
# LAB 2: BLOCK CIPHERS
# =====================================================

# --- DES ---
def des_enc(pt,key8):
    c=DES.new(key8,DES.MODE_ECB)
    return c.encrypt(pad(pt,8))
def des_dec(ct,key8):
    return unpad(DES.new(key8,DES.MODE_ECB).decrypt(ct))

# --- 3DES ---
def tdes_enc(pt,key):
    key=DES3.adjust_key_parity(key)
    c=DES3.new(key,DES3.MODE_ECB)
    return c.encrypt(pad(pt,8))
def tdes_dec(ct,key):
    key=DES3.adjust_key_parity(key)
    return unpad(DES3.new(key,DES3.MODE_ECB).decrypt(ct))

# --- AES (ECB, CBC, CTR) ---
def aes_ecb_enc(pt,key): return AES.new(key,AES.MODE_ECB).encrypt(pad(pt,16))
def aes_ecb_dec(ct,key): return unpad(AES.new(key,AES.MODE_ECB).decrypt(ct))
def aes_cbc_enc(pt,key,iv): return AES.new(key,AES.MODE_CBC,iv=iv).encrypt(pad(pt,16))
def aes_cbc_dec(ct,key,iv): return unpad(AES.new(key,AES.MODE_CBC,iv=iv).decrypt(ct))
def aes_ctr_enc(pt,key,nonce): return AES.new(key,AES.MODE_CTR,nonce=nonce).encrypt(pt)
aes_ctr_dec = aes_ctr_enc  # CTR encrypt/decrypt are identical

# =====================================================
# LAB 3: RSA, ElGamal, DH, ECC
# =====================================================

# --- RSA ---
def rsa_key(bits=2048):
    k = RSA.generate(bits)
    return k, k.publickey()

def rsa_enc(m,pub):
    # PKCS1_OAEP.new accepts the public key object
    return PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(m)

def rsa_dec(c,prv):
    return PKCS1_OAEP.new(prv, hashAlgo=SHA256).decrypt(c)

# --- ElGamal ---
def elg_key(bits=256):
    p=number.getPrime(bits); g=2; x=random.randrange(2,p-1); h=pow(g,x,p)
    return p,g,h,x
def elg_enc(m,p,g,h):
    k=random.randrange(2,p-1)
    return pow(g,k,p),(m*pow(h,k,p))%p
def elg_dec(c1,c2,p,x): return (c2*modinv(pow(c1,x,p),p))%p

# --- Diffie-Hellman ---
def dh_params(bits=256): p=number.getPrime(bits); return p,2
def dh_keypair(p,g): a=random.randrange(2,p-2); return a,pow(g,a,p)
def dh_shared(p,a,B): return pow(B,a,p)

# --- ECC (simple ECIES-like) ---
def ecies_enc(pt,rec_pub):
    eph=ECC.generate(curve='P-256')
    # shared secret: multiply ephemeral public point with recipient private scalar
    s=eph.pointQ * rec_pub.d
    z=int(s.x).to_bytes(32,'big')
    key=HKDF(z,32,b"ecies",SHA256)
    iv=get_random_bytes(12)
    c=AES.new(key,AES.MODE_GCM,nonce=iv); ct,tag=c.encrypt_and_digest(pt)
    return eph.export_key(format='DER'),iv,ct,tag

def ecies_dec(eph_der,iv,ct,tag,rec_prv):
    eph=ECC.import_key(eph_der)
    s=eph.pointQ * rec_prv.d
    z=int(s.x).to_bytes(32,'big'); key=HKDF(z,32,b"ecies",SHA256)
    return AES.new(key,AES.MODE_GCM,nonce=iv).decrypt_and_verify(ct,tag)

# =====================================================
# LAB 4: RABIN
# =====================================================
def rabin_key(bits=256):
    def gp():
        while True:
            p=number.getPrime(bits//2)
            if p%4==3: return p
    p=gp(); q=gp(); return p*q,p,q
def rabin_enc(m,n): return pow(m,2,n)
def rabin_dec(c,n,p,q):
    mp=pow(c,(p+1)//4,p); mq=pow(c,(q+1)//4,q)
    yp=modinv(p,q); yq=modinv(q,p)
    r1=(mp*q*yq+mq*p*yp)%n; r2=n-r1; r3=(mp*q*yq-mq*p*yp)%n; r4=n-r3
    return [r1,r2,r3,r4]

# =====================================================
# DEMOS WITH EXPLANATION
# =====================================================
if __name__ == "__main__":
    print("\n=== LAB 1: Classical Ciphers ===")
    msg="HELLOWORLD"
    print("Original:",msg)

    # Caesar
    ct=caesar_enc(msg,3); print("Caesar Enc:",ct); print("Caesar Dec:",caesar_dec(ct,3))

    # Affine
    ct=affine_enc(msg,5,8); print("\nAffine Enc:",ct); print("Affine Dec:",affine_dec(ct,5,8))

    # Vigenere
    ct=vig_enc(msg,"KEY"); print("\nVigenere Enc:",ct); print("Vigenere Dec:",vig_dec(ct,"KEY"))

    # Autokey
    ct=autokey_enc(msg,"K"); print("\nAutokey Enc:",ct); print("Autokey Dec:",autokey_dec(ct,"K"))

    # Playfair
    ct=playfair_enc("HIDETHEGOLD","MONARCHY")
    print("\nPlayfair Enc:",ct); print("Playfair Dec:",playfair_dec(ct,"MONARCHY"))

    # Hill (2x2)
    ct=hill_enc("HELP",(3,3,2,7))
    print("\nHill Enc:",ct); print("Hill Dec:",hill_dec(ct,(3,3,2,7)))

    # Transposition
    ct=transpose_enc(msg,5)
    print("\nTranspose Enc:",ct); print("Transpose Dec:",transpose_dec(ct,5))

    print("\n=== LAB 2: Symmetric Ciphers ===")
    # DES
    key8=b"A1B2C3D4"
    ct=des_enc(b"SecretMsg",key8)
    print("DES Enc:",ct); print("DES Dec:",des_dec(ct,key8))

    # 3DES
    key24=DES3.adjust_key_parity(get_random_bytes(24))
    ct=tdes_enc(b"Classified",key24)
    print("\n3DES Enc:",ct); print("3DES Dec:",tdes_dec(ct,key24))

    # AES-128 ECB
    key16=b"0123456789ABCDEF"
    ct=aes_ecb_enc(b"SensitiveData",key16)
    print("\nAES-128 ECB Enc:",ct); print("AES-128 ECB Dec:",aes_ecb_dec(ct,key16))

    # AES-CBC
    iv=get_random_bytes(16)
    ct=aes_cbc_enc(b"TopSecretInfo",key16,iv)
    print("\nAES-CBC Enc:",ct); print("AES-CBC Dec:",aes_cbc_dec(ct,key16,iv))

    # AES-CTR
    nonce=get_random_bytes(8)
    ct=aes_ctr_enc(b"CounterMode",key16,nonce)
    print("\nAES-CTR Enc:",ct); print("AES-CTR Dec:",aes_ctr_dec(ct,key16,nonce))

    print("\n=== LAB 3: Asymmetric Ciphers ===")
    # RSA
    prv,pub=rsa_key()
    ct=rsa_enc(b"Asymmetric Encryption",pub)
    print("RSA Enc:",ct); print("RSA Dec:",rsa_dec(ct,prv))

    # ElGamal
    P,G,H,X=elg_key()
    m=12345
    c1,c2=elg_enc(m,P,G,H)
    print("\nElGamal Enc:",(c1,c2)); print("ElGamal Dec:",elg_dec(c1,c2,P,X))

    # Diffie-Hellman
    p,g=dh_params(); a,A=dh_keypair(p,g); b,B=dh_keypair(p,g)
    print("\nDH Shared Secret (both sides):",dh_shared(p,a,B),dh_shared(p,b,A))

    # ECC ECIES
    ecc=ECC.generate(curve='P-256')
    eph,iv,ct,tag=ecies_enc(b"ECC secure message",ecc)
    print("\nECC Enc (ciphertext shown):",ct)
    print("ECC Dec:",ecies_dec(eph,iv,ct,tag,ecc))

    print("\n=== LAB 4: Rabin ===")
    n,p,q=rabin_key()
    m=int.from_bytes(b"Hi","big")
    c=rabin_enc(m,n)
    roots=rabin_dec(c,n,p,q)
    print("Rabin Enc:",c)
    print("Rabin Dec candidates:",[r.to_bytes((r.bit_length()+7)//8,'big') for r in roots])
