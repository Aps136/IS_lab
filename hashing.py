def custom_hash(input_string):
    hash_value = 5381
    for char in input_string:
        # Multiply by 33 and add ASCII value of char
        hash_value = (hash_value * 33) + ord(char)

        # Bitwise mixing (here a simple left shift and XOR)
        hash_value = (hash_value << 5) ^ hash_value

        # Keep in 32-bit range
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value

# Example usage
text = "Hello, world!"
print(f"Hash of '{text}': {custom_hash(text)}")
