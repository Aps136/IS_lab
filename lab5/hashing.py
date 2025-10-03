import hashlib

def compute_hash(data):
    # Encode string into bytes and compute SHA-256
    return hashlib.sha256(data.encode()).hexdigest()

# Example message
message = "This is a secure message."
hash_value = compute_hash(message)

print("Message:", message)
print("SHA-256 Hash:", hash_value)

# Let's check integrity by recomputing
new_message = "This is a secure message."   # same message
tampered_message = "This is a tampered message."  # modified

print("\nChecking integrity:")
print("Original hash:", hash_value)
print("Hash of new_message:", compute_hash(new_message))
print("Hash of tampered_message:", compute_hash(tampered_message))
