def encode(text, shift):
    encoded_text = ''

    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encoded_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encoded_text += char  # Keep non-alphabet characters as they are

    return encoded_text


def decode(text, shift):
    decoded_text = ''

    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            decoded_text += chr((ord(char) - shift_base - shift) % 26 + shift_base)
        else:
            decoded_text += char  # Keep non-alphabet characters as they are

    return decoded_text

text = "I am learning information security"
shift = 20
encoded = encode(text, shift)
print(f"Encoded: {encoded}")
decoded = decode(encoded, shift)
print(f"Decoded: {decoded}")
