import numpy as np


# --- Helper function for modular inverse ---
def mod_inverse(a, m):
    """
    Computes the modular multiplicative inverse of a mod m.
    Returns the inverse or None if it doesn't exist.
    """
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


# --- Main Hill Cipher functions ---
def hill_cipher_3x3_encrypt(plaintext, key_matrix):
    """Encrypts plaintext using a 3x3 Hill cipher key."""
    plaintext = plaintext.upper().replace(" ", "").replace(".", "").replace(",", "").strip()

    # Pad the plaintext if its length is not a multiple of 3
    if len(plaintext) % 3 != 0:
        plaintext += "X" * (3 - (len(plaintext) % 3))

    # Check if the key matrix is invertible mod 26
    det = int(np.round(np.linalg.det(key_matrix)))
    det_inv = mod_inverse(det % 26, 26)
    if det_inv is None:
        return "Error: The key matrix is not invertible modulo 26."

    # Map letters to numbers
    text_to_num = [ord(char) - ord('A') for char in plaintext]

    ciphertext = ""
    for i in range(0, len(text_to_num), 3):
        # Create the plaintext vector
        p_vector = np.array(text_to_num[i:i + 3]).reshape(3, 1)

        # Multiply by the key matrix and apply modulo 26
        c_vector = np.dot(key_matrix, p_vector) % 26

        # Map numbers back to letters
        for num in c_vector.flatten():
            ciphertext += chr(num + ord('A'))

    return ciphertext


def hill_cipher_3x3_decrypt(ciphertext, key_matrix):
    """Decrypts ciphertext using a 3x3 Hill cipher key."""
    # Check if the key matrix is invertible mod 26
    det = int(np.round(np.linalg.det(key_matrix)))
    det_inv = mod_inverse(det % 26, 26)
    if det_inv is None:
        return "Error: The key matrix is not invertible modulo 26."

    # Calculate the inverse of the key matrix mod 26
    adjugate = np.round(det * np.linalg.inv(key_matrix)).astype(int)
    adjugate_mod_26 = adjugate % 26

    key_inverse = (det_inv * adjugate_mod_26) % 26

    # Map letters to numbers
    text_to_num = [ord(char) - ord('A') for char in ciphertext]

    plaintext = ""
    for i in range(0, len(text_to_num), 3):
        # Create the ciphertext vector
        c_vector = np.array(text_to_num[i:i + 3]).reshape(3, 1)

        # Multiply by the inverse key matrix and apply modulo 26
        p_vector = np.dot(key_inverse, c_vector) % 26

        # Map numbers back to letters
        for num in p_vector.flatten():
            plaintext += chr(num + ord('A'))

    return plaintext


# --- Example Usage ---
if __name__ == '__main__':
    # A 3x3 key matrix that is invertible mod 26
    key = np.array([[6, 24, 1],
                    [13, 16, 10],
                    [20, 17, 15]])

    plaintext_msg = "Hill Cipher"

    # Encryption
    encrypted_msg = hill_cipher_3x3_encrypt(plaintext_msg, key)
    print(f"Plaintext: {plaintext_msg}")
    print(f"Encrypted message: {encrypted_msg}")

    # Decryption
    decrypted_msg = hill_cipher_3x3_decrypt(encrypted_msg, key)
    print(f"Decrypted message: {decrypted_msg}")
