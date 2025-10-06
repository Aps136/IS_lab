class add:
    def __init__(self, pt='', key=1):
        self.pt = pt
        self.key = key

    def encrypt(self, pt=None, key=None):
        pt = self.pt if pt is None else pt
        key = self.key if key is None else key
        pt_ord = [ord(i) for i in pt]
        ct_ord = [(i + key) % 128 for i in pt_ord]
        return "".join([chr(i) for i in ct_ord])

    def decrypt(self, ct, key=None):
        key = self.key if key is None else key
        ct_ord = [ord(i) for i in ct]
        pt_ord = [(i - key) % 128 for i in ct_ord]
        return "".join([chr(i) for i in pt_ord])


class mul:
    def __init__(self, pt='', key=1):
        self.pt = pt
        self.key = key

    def eea(self, a, b):
        km = 0
        ka = 1
        while a % b != 0:
            q = a // b
            rem = a % b
            k = km - ka * q
            km = ka
            ka = k
            a = b
            b = rem
        return ka

    def encrypt(self, pt=None, key=None):
        pt = self.pt if pt is None else pt
        key = self.key if key is None else key
        pt_ord = [ord(i) for i in pt]
        ct_ord = [(i * key) % 128 for i in pt_ord]
        return "".join([chr(i) for i in ct_ord])

    def decrypt(self, ct, key=None):
        key = self.key if key is None else key
        kinv = self.eea(128, key)
        ct_ord = [ord(i) for i in ct]
        pt_ord = [(i * kinv) % 128 for i in ct_ord]
        return "".join([chr(i) for i in pt_ord])


class affine:
    def __init__(self, pt, km, ka):
        self.pt = pt
        self.km = km
        self.ka = ka

    def encrypt(self, pt=None, km=None, ka=None):
        pt = self.pt if pt is None else pt
        km = self.km if km is None else km
        ka = self.ka if ka is None else ka

        pt_ord = [ord(i) for i in pt]
        ct_ord = [((i * km) + ka) % 128 for i in pt_ord]
        return "".join([chr(i) for i in ct_ord])

    def decrypt(self, ct, km=None, ka=None):
        km = self.km if km is None else km
        ka = self.ka if ka is None else ka

        kminv = mul.eea(self, 128, km)
        ct_ord = [ord(i) for i in ct]
        pt_ord = [((i - ka) * kminv) % 128 for i in ct_ord]
        return "".join([chr(i) for i in pt_ord])


class autokey:
    def __init__(self, pt='', key=1):
        self.pt = pt
        self.key = key

    def encrypt(self, pt=None, key=None):
        pt = self.pt if pt is None else pt
        key = self.key if key is None else key

        pt_ord = [ord(i) for i in pt]
        keys = [key]
        keys.extend(pt_ord[:-1])
        ct_ord = [(pt_ord[i] + keys[i]) % 128 for i in range(len(pt_ord))]
        return "".join([chr(i) for i in ct_ord])

    def decrypt(self, ct, key=None):
        key = self.key if key is None else key
        ct_ord = [ord(i) for i in ct]
        keys = list([key])
        pt_ord = []
        for i in range(len(ct_ord)):
            pt_ord.append((ct_ord[i] - keys[i]) % 128)
            keys.append(pt_ord[-1])

        return "".join([chr(i) for i in pt_ord])


class vigenere:
    def __init__(self, pt='demo', key='txt'):
        self.pt = pt
        self.key = key

    def encrypt(self, pt=None, key=None):
        pt = self.pt if pt is None else pt
        key = self.key if key is None else key

        pt_ord = [ord(i) for i in pt]
        ct_ord = [(pt_ord[i] + ord(key[i % len(key)])) % 128 for i in range(len(pt_ord))]
        return "".join([chr(i) for i in ct_ord])

    def decrypt(self, ct, key=None):
        key = self.key if key is None else key
        ct_ord = [ord(i) for i in ct]
        pt_ord = [(ct_ord[i] - ord(key[i % len(key)])) % 128 for i in range(len(ct_ord))]
        return "".join([chr(i) for i in pt_ord])


import numpy as np


class hill_all:
    def __init__(self, pt, key):
        self.pt = pt.lower()
        self.key = np.array(key)

    def encrypt(self, pt=None, key=None):
        key = self.key if key is None else np.array(key)
        pt = self.pt if pt is None else pt.lower()

        # --- Key validation ---
        if key.ndim != 2:
            raise ValueError("Key must be 2D")
        if key.shape[0] != key.shape[1]:
            raise ValueError("Key must be square")

        dim = key.shape[0]

        # --- Plaintext padding ---
        extra = (-len(pt)) % dim
        pt += 'z' * extra

        pt_nums = [ord(c) for c in pt]
        pt_matrix = np.array([pt_nums[i:i + dim] for i in range(0, len(pt_nums), dim)])

        ct_matrix = (pt_matrix @ key) % 128

        # Convert back to letters
        ct = "".join(chr(num) for row in ct_matrix for num in row)
        return ct

    def decrypt(self, ct, key=None):
        key = self.key if key is None else np.array(key)

        # --- Key validation ---
        if key.ndim != 2 or key.shape[0] != key.shape[1]:
            raise ValueError("Key must be square")

        dim = key.shape[0]

        # --- Compute modular inverse of key ---
        det = int(round(np.linalg.det(key))) % 128
        det_inv = pow(det, -1, 128)  # modular inverse of determinant

        # Matrix of minors, cofactors, adjugate
        adjugate = np.round(det * np.linalg.inv(key)).astype(int) % 128

        key_inv = (det_inv * adjugate) % 128

        # --- Ciphertext processing ---
        ct_nums = [ord(c) for c in ct]
        ct_matrix = np.array([ct_nums[i:i + dim] for i in range(0, len(ct_nums), dim)])

        pt_matrix = (ct_matrix @ key_inv) % 128
        pt = "".join(chr(num) for row in pt_matrix for num in row)
        return pt


class Hill:
    def __init__(self, pt, key):
        self.pt = pt.lower()
        self.key = np.array(key)

    def encrypt(self, pt=None, key=None):
        key = self.key if key is None else np.array(key)
        pt = self.pt if pt is None else pt.lower()

        # --- Key validation ---
        if key.ndim != 2 or key.shape[0] != key.shape[1]:
            raise ValueError("Key must be square")

        dim = key.shape[0]

        # --- Plaintext padding ---
        extra = (-len(pt)) % dim
        pt += 'z' * extra

        # Convert chars → numbers
        pt_nums = [ord(c) - ord('a') for c in pt]
        pt_matrix = np.array([pt_nums[i:i + dim] for i in range(0, len(pt_nums), dim)])

        # --- Encryption ---
        ct_matrix = (pt_matrix @ key) % 26
        ct = "".join(chr(num + ord('a')) for row in ct_matrix for num in row)
        return ct

    def decrypt(self, ct, key=None):
        key = self.key if key is None else np.array(key)

        # --- Key validation ---
        if key.ndim != 2 or key.shape[0] != key.shape[1]:
            raise ValueError("Key must be square")

        dim = key.shape[0]

        # --- Compute modular inverse of key ---
        det = int(round(np.linalg.det(key))) % 26
        det_inv = pow(det, -1, 26)  # modular inverse of determinant

        # Matrix of minors, cofactors, adjugate
        adjugate = np.round(det * np.linalg.inv(key)).astype(int) % 26

        key_inv = (det_inv * adjugate) % 26

        # --- Ciphertext processing ---
        ct_nums = [ord(c) - ord('a') for c in ct]
        ct_matrix = np.array([ct_nums[i:i + dim] for i in range(0, len(ct_nums), dim)])

        pt_matrix = (ct_matrix @ key_inv) % 26
        pt = "".join(chr(num + ord('a')) for row in pt_matrix for num in row)
        return pt


import random as rd


class playfair:
    def __init__(self, pt=None, key=None):
        self.key = key
        self.pt = pt

    def generate_key(self):
        ss = 'qwertyuopasdfghjklzxcvbnm'
        ss = [i for i in ss]
        key = []
        for i in range(len(ss)):
            rest = [i for i in ss if i not in key]
            ele = rd.choice(rest)
            key.append(ele)
        key = [key[i:i + 5] for i in range(0, len(key), 5)]
        print(key)
        return key

    def findindex(self, key, pair):
        a = None
        b = None
        for i in range(5):
            for j in range(5):
                if key[i][j] == pair[0]:
                    a = [i, j]
                if key[i][j] == pair[1]:
                    b = [i, j]
        return [a, b]

    def encrypt(self, pt=None, key=None):
        pt = self.pt if pt is None else pt
        key = self.key if key is None else key
        if not (len(key) == 5 and len(key[0]) == 5):
            raise ValueError("wrong key expected 5x5 matrix")
        pt = pt.lower()
        pt = ['j' if i == 'i' else i for i in pt]
        pt = "".join([i for i in pt if i.isalnum()])

        if len(pt) % 2 == 1:
            pt = pt + 'z'

        ct = ""
        for i in range(0, len(pt), 2):
            pair = pt[i:i + 2]
            ca, cb = '', ''
            a, b = self.findindex(key, pair)
            if a[0] == b[0]:
                ca = key[a[0]][(a[1] + 1) % 5]
                cb = key[b[0]][(b[1] + 1) % 5]
            elif a[1] == b[1]:
                ca = key[(a[0] + 1) % 5][a[1]]
                cb = key[(b[0] + 1) % 5][b[1]]
            else:
                ca = key[a[0]][b[1]]
                cb = key[b[0]][a[1]]
            ct += "".join([ca, cb])
        return ct

    def decrypt(self, ct, key=None):
        ct = self.ct if ct is None else ct
        key = self.key if key is None else key
        if not (len(key) == 5 and len(key[0]) == 5):
            raise ValueError("wrong key expected 5x5 matrix")

        pt = ""
        for i in range(0, len(ct), 2):
            pair = ct[i:i + 2]
            pa, pb = '', ''
            a, b = self.findindex(key, pair)
            if a[0] == b[0]:
                pa = key[a[0]][(a[1] - 1) % 5]
                pb = key[b[0]][(b[1] - 1) % 5]
            elif a[1] == b[1]:
                pa = key[(a[0] - 1) % 5][a[1]]
                pb = key[(b[0] - 1) % 5][b[1]]
            else:
                pa = key[a[0]][b[1]]
                pb = key[b[0]][a[1]]
            pt += "".join([pa, pb])
        return pt


import math, random, time
from Crypto.Cipher import DES, DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
import hashlib
import sys


# helper functions
# PKCS7 padding for block ciphers
def pad(b: bytes, bs: int) -> bytes:
    p = bs - (len(b) % bs)
    return b + bytes([p]) * p


def unpad(b: bytes) -> bytes:
    if not b: return b
    p = b[-1]
    return b[:-p]


clean = lambda s: "".join(c for c in s.upper() if c.isalpha())
modinv = lambda a, m: pow(a, -1, m)


def transpose_enc(pt, cols):
    p = clean(pt);
    rows = math.ceil(len(p) / cols)
    grid = [p[i * cols:(i + 1) * cols].ljust(cols, "X") for i in range(rows)]
    return "".join("".join(r[c] for r in grid) for c in range(cols))


def transpose_dec(ct, cols):
    ctext = clean(ct);
    rows = math.ceil(len(ctext) / cols)
    it = iter(ctext);
    grid = [[""] * cols for _ in range(rows)]
    for c in range(cols):
        for r in range(rows): grid[r][c] = next(it)
    return "".join("".join(r) for r in grid).rstrip("X")


# --- DES ---
def des_enc(pt, key8):
    c = DES.new(key8, DES.MODE_ECB)
    return c.encrypt(pad(pt, 8))


def des_dec(ct, key8):
    return unpad(DES.new(key8, DES.MODE_ECB).decrypt(ct))


# --- 3DES ---
def tdes_enc(pt, key):
    key = DES3.adjust_key_parity(key)
    c = DES3.new(key, DES3.MODE_ECB)
    return c.encrypt(pad(pt, 8))


def tdes_dec(ct, key):
    key = DES3.adjust_key_parity(key)
    return unpad(DES3.new(key, DES3.MODE_ECB).decrypt(ct))


# --- AES (ECB, CBC, CTR) ---
def aes_ecb_enc(pt, key): return AES.new(key, AES.MODE_ECB).encrypt(pad(pt, 16))


def aes_ecb_dec(ct, key): return unpad(AES.new(key, AES.MODE_ECB).decrypt(ct))


def aes_cbc_enc(pt, key, iv): return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pad(pt, 16))


def aes_cbc_dec(ct, key, iv): return unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct))


def aes_ctr_enc(pt, key, nonce): return AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(pt)


aes_ctr_dec = aes_ctr_enc


# --- RSA ---
def rsa_key(bits=1024): k = RSA.generate(bits); return k, k.publickey()


def rsa_enc(m, pub): return PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(m)


def rsa_dec(c, prv): return PKCS1_OAEP.new(prv, hashAlgo=SHA256).decrypt(c)


# --- ElGamal ---
def elg_key(bits=256):
    p = number.getPrime(bits);
    g = 2;
    x = random.randrange(2, p - 1);
    h = pow(g, x, p)
    return p, g, h, x


def elg_enc(m, p, g, h):
    k = random.randrange(2, p - 1)
    return pow(g, k, p), (m * pow(h, k, p)) % p


def elg_dec(c1, c2, p, x): return (c2 * modinv(pow(c1, x, p), p)) % p


# --- Diffie-Hellman ---
def dh_params(bits=256): p = number.getPrime(bits); return p, 2


def dh_keypair(p, g): a = random.randrange(2, p - 2); return a, pow(g, a, p)


def dh_shared(p, a, B): return pow(B, a, p)


# --- ECC (simple ECIES-like) ---
def ecies_enc(pt, rec_pub):
    # Generate an ephemeral key pair for this encryption session
    eph = ECC.generate(curve='P-256')

    # Correctly derive the shared secret 's' using the recipient's public key
    # and the ephemeral private key.
    s = rec_pub.pointQ * eph.d  # <-- THIS LINE IS FIXED

    # Use HKDF to derive a symmetric key 'key' from the shared secret's x-coordinate
    z = int(s.x).to_bytes(32, 'big')
    key = HKDF(z, 32, b"ecies", SHA256)

    # Encrypt the plaintext using AES-GCM
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(pt)

    # Return the ephemeral public key (needed for decryption) along with the ciphertext
    return eph.export_key(format='DER'), iv, ct, tag


def ecies_dec(eph_der, iv, ct, tag, rec_prv):
    eph = ECC.import_key(eph_der);
    s = eph.pointQ * rec_prv.d
    z = int(s.x).to_bytes(32, 'big');
    key = HKDF(z, 32, b"ecies", SHA256)
    return AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)


# rabin
def rabin_key(bits=1024):
    def gp():
        while True:
            p = number.getPrime(bits // 2)
            if p % 4 == 3: return p

    p = gp();
    q = gp();
    return p * q, p, q


def rabin_enc(m, n): return pow(m, 2, n)


def rabin_dec(c, n, p, q):
    mp = pow(c, (p + 1) // 4, p);
    mq = pow(c, (q + 1) // 4, q)
    yp = modinv(p, q);
    yq = modinv(q, p)
    r1 = (mp * q * yq + mq * p * yp) % n;
    r2 = n - r1;
    r3 = (mp * q * yq - mq * p * yp) % n;
    r4 = n - r3
    return [r1, r2, r3, r4]


from Crypto.Hash import SHA256, MD5, SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP


# --- Lab 5: Hashing Functions ---

def djb2_hash(s: str) -> int:
    hash_val = 5381  # Initial hash value
    for char in s:
        # (hash * 33) + char_ascii_value
        hash_val = ((hash_val << 5) + hash_val) + ord(char)
    # Ensure the hash is kept within a 32-bit range
    return hash_val & 0xFFFFFFFF


# Standard hashing algorithms for comparison (Corrected)
def md5_hash(data: bytes) -> bytes:
    return MD5.new(data=data).digest()


def sha1_hash(data: bytes) -> bytes:
    return SHA1.new(data=data).digest()


def sha256_hash(data: bytes) -> bytes:
    return SHA256.new(data=data).digest()


# --- Lab 6: Digital Signature Functions  ---
# These functions now use the recommended PKCS#1 v1.5 signature scheme.

def rsa_sign(msg: bytes, prv_key) -> bytes:
    """
    Creates a digital signature for a message using an RSA private key
    and the PKCS#1 v1.5 signature scheme.
    """
    # Use SHA-256 for a secure hash
    h = SHA256.new(msg)
    # Create a signer object using the private key and the PKCS#1 v1.5 scheme
    signer = pkcs1_15.new(prv_key)
    signature = signer.sign(h)
    return signature


def rsa_verify(msg: bytes, signature: bytes, pub_key) -> bool:
    """
    Verifies a digital signature using the corresponding RSA public key
    and the PKCS#1 v1.5 signature scheme.
    """
    h = SHA256.new(msg)
    # Create a verifier object using the public key
    verifier = pkcs1_15.new(pub_key)
    try:
        # The verify method raises an exception on failure
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# Helper functions for Schnorr signature algorithm
def generate_schnorr_params(bits=512):
    """Generate parameters for Schnorr signature (p, q, g)."""
    q = number.getPrime(160)
    while True:
        # Find a prime p such that p-1 is a multiple of q
        k = number.getRandomNBitInteger(bits - 160)
        p = k * q + 1
        if number.isPrime(p):
            break

    # Find a generator g
    while True:
        h = random.randint(2, p - 2)
        g = pow(h, (p - 1) // q, p)
        if g > 1:
            break

    return p, q, g


def schnorr_keygen(p, q, g):
    """Generate a Schnorr key pair (private key x, public key y)."""
    x = random.randint(1, q - 1)  # Private key
    y = pow(g, x, p)  # Public key
    return x, y


def schnorr_sign(msg: bytes, p, q, g, x):
    """Create a Schnorr signature (r, s) for a message."""
    k = random.randint(1, q - 1)  # Ephemeral secret
    r = pow(g, k, p)

    # Create hash e = H(r || m)
    hasher = hashlib.sha256()
    hasher.update(r.to_bytes((r.bit_length() + 7) // 8, 'big'))
    hasher.update(msg)
    e = int.from_bytes(hasher.digest(), 'big')

    s = (k - x * e) % q
    return r, s


def schnorr_verify(msg: bytes, signature, p, g, y):
    """Verify a Schnorr signature."""
    r, s = signature

    # Create hash e = H(r || m)
    hasher = hashlib.sha256()
    hasher.update(r.to_bytes((r.bit_length() + 7) // 8, 'big'))
    hasher.update(msg)
    e = int.from_bytes(hasher.digest(), 'big')

    # Calculate rv = g^s * y^e mod p
    rv = (pow(g, s, p) * pow(y, e, p)) % p

    # The signature is valid if rv == r
    return rv == r


def generate_dh_params(bits: int = 256):
    """
    Generates public Diffie-Hellman parameters: a prime 'p' and a generator 'g'.

    Args:
        bits: The number of bits for the prime number p.

    Returns:
        A tuple containing the prime (p) and generator (g).
    """
    # 1. Generate a large prime number 'p'
    p = number.getPrime(bits)

    # 2. 'g' is often a small number, typically 2 or 5. We'll use 2.
    g = 2

    return p, g


def generate_keypair(p: int, g: int):
    """
    Generates a private and public key for one party.

    Args:
        p: The public prime number.
        g: The public generator.

    Returns:
        A tuple containing the private key and the public key.
    """
    # 1. Choose a secret private key 'a' (a random integer)
    private_key = random.randint(2, p - 2)

    # 2. Calculate the public key 'A' using: A = g^a mod p
    public_key = pow(g, private_key, p)

    return private_key, public_key


def calculate_shared_secret(their_public_key: int, my_private_key: int, p: int) -> int:
    """
    Calculates the shared secret.

    Args:
        their_public_key: The public key received from the other party.
        my_private_key: Your own private key.
        p: The public prime number.

    Returns:
        The calculated shared secret.
    """
    # Calculate the shared secret 's' using: s = B^a mod p
    shared_secret = pow(their_public_key, my_private_key, p)
    return shared_secret


def elgamal_keygen(bits=256):
    """Generates keys for the ElGamal signature scheme."""
    p = number.getPrime(bits)
    g = 2  # A common generator
    x = random.randint(2, p - 2)  # Private key
    y = pow(g, x, p)  # Public key
    return {'p': p, 'g': g, 'y': y}, {'p': p, 'g': g, 'x': x}


def elgamal_sign(msg_hash: bytes, private_key: dict):
    """Signs a message hash using an ElGamal private key."""
    p = private_key['p']
    g = private_key['g']
    x = private_key['x']

    # Convert hash to an integer
    h = int.from_bytes(msg_hash, 'big')

    while True:
        k = random.randint(2, p - 2)
        if number.GCD(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)

    return r, s


def elgamal_verify(msg_hash: bytes, signature: tuple, public_key: dict) -> bool:
    """Verifies an ElGamal signature."""
    p = public_key['p']
    g = public_key['g']
    y = public_key['y']
    r, s = signature

    if not (0 < r < p):
        return False

    h = int.from_bytes(msg_hash, 'big')

    # Verification check: (y^r * r^s) mod p == g^h mod p
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)

    return v1 == v2
