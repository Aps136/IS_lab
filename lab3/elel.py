import random
import sympy

# The size of the prime number in bits.
KEY_SIZE_BITS = 512


def generate_key_pair():
    """
    Generates a public and private key for ElGamal encryption.

    The key generation process involves:
    1. Finding a large prime number 'p'.
    2. Finding a generator 'g' for the multiplicative group modulo 'p'.
    3. Choosing a random private key 'x'.
    4. Calculating the public key 'y' as g^x mod p.
    """
    # 1. Find a large prime p.
    # We use a secure random number generation for p.
    p = sympy.randprime(2 ** (KEY_SIZE_BITS - 1), 2 ** KEY_SIZE_BITS)

    # 2. Find a generator g.
    # A generator is an element whose powers generate all the elements of the group.
    # We find one by testing random numbers until we find one that is a generator.
    g = 0
    q = (p - 1) // 2
    while True:
        g = random.randint(2, p - 2)
        if pow(g, q, p) != 1:
            break

    # 3. Choose a random private key x.
    x = random.randint(1, p - 2)

    # 4. Calculate the public key y.
    y = pow(g, x, p)

    # The public key consists of (p, g, y)
    public_key = (p, g, y)
    # The private key is x
    private_key = x

    return public_key, private_key


def encrypt(public_key, message):
    """
    Encrypts a message using the ElGamal algorithm.

    The encryption process involves:
    1. Converting the message string to an integer.
    2. Choosing a random integer 'k' (ephemeral key).
    3. Calculating the ciphertext components c1 and c2.

    Returns the ciphertext, which is a pair (c1, c2).
    """
    p, g, y = public_key

    # Convert message to an integer.
    message_int = int.from_bytes(message.encode('utf-8'), 'big')

    if message_int >= p:
        raise ValueError("Message is too large to be encrypted with this key.")

    # Choose a random ephemeral key k.
    k = random.randint(1, p - 2)

    # Calculate the ciphertext components.
    c1 = pow(g, k, p)
    c2 = (message_int * pow(y, k, p)) % p

    return (c1, c2)


def decrypt(private_key, ciphertext, p):
    """
    Decrypts a ciphertext using the ElGamal algorithm.

    The decryption process involves:
    1. Calculating the modular inverse of c1^x mod p.
    2. Multiplying c2 by the inverse to recover the original message integer.
    3. Converting the integer back to a string.

    Returns the original message string.
    """
    x = private_key
    c1, c2 = ciphertext

    # Calculate s = c1^x mod p.
    s = pow(c1, x, p)

    # Calculate the modular inverse of s.
    s_inv = pow(s, -1, p)

    # Recover the message integer.
    message_int = (c2 * s_inv) % p

    # Convert the integer back to bytes and then to a string.
    # The number of bytes is determined by the integer value.
    num_bytes = (message_int.bit_length() + 7) // 8
    message = message_int.to_bytes(num_bytes, 'big').decode('utf-8')

    return message


# --- Example Usage ---
if __name__ == '__main__':
    # You will need to install the sympy library for this code to run.
    # Use: pip install sympy

    # Step 1: Alice generates her key pair.
    # This process is computationally intensive, especially for larger keys.
    public_key, private_key = generate_key_pair()
    print("ElGamal key pair generated successfully.")

    # Step 2: Bob wants to send a secret message to Alice.
    # He uses Alice's public key to encrypt the message.
    original_message = "This is a secret message for Alice."
    print(f"\nOriginal Message: {original_message}")

    c1, c2 = encrypt(public_key, original_message)
    print(f"Encrypted message (c1, c2): ({c1}, {c2})")

    # Step 3: Alice receives the ciphertext and decrypts it using her private key.
    p, _, _ = public_key
    decrypted_message = decrypt(private_key, (c1, c2), p)

    print(f"\nDecrypted Message: {decrypted_message}")

    # Verification
    if original_message == decrypted_message:
        print("\nSUCCESS: The original and decrypted messages match!")
    else:
        print("\nFAILURE: Decryption did not produce the original message.")
