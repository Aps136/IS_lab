# q3_performance_analysis.py
import time
import random
import string
from helper import md5_hash, sha1_hash, sha256_hash
#q1
# q1_hash_implementation.py
from helper import djb2_hash


def main():
    """Demonstrates the usage of the djb2_hash function."""
    input_string1 = "Hello World"
    input_string2 = "This is a test of the djb2 hash function."

    # Compute hash for the first string
    hash1 = djb2_hash(input_string1)

    # Compute hash for the second string
    hash2 = djb2_hash(input_string2)

    print("--- DJB2 Hash Function Demonstration ---\n")
    print(f"Input String: '{input_string1}'")
    print(f"Hash Value (integer): {hash1}")
    print(f"Hash Value (hex): {hex(hash1)}\n")

    print(f"Input String: '{input_string2}'")
    print(f"Hash Value (integer): {hash2}")
    print(f"Hash Value (hex): {hex(hash2)}")


if __name__ == "__main__":
    main()

#q3
def generate_random_strings(count, min_len=50, max_len=1500):
    """Generates a list of random alphanumeric strings."""
    strings = []
    for _ in range(count):
        length = random.randint(min_len, max_len)
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        strings.append(s)
    return strings


def measure_hash_time(hash_function, data):
    """Measures the execution time for hashing all items in a dataset."""
    start_time = time.perf_counter()
    for item in data:
        hash_function(item.encode())  # Hash functions require byte strings
    end_time = time.perf_counter()
    return end_time - start_time


def find_collisions(hash_function, data):
    """Checks for hash collisions in a dataset."""
    hashes_seen = set()
    collisions_found = 0
    for item in data:
        # Convert the hash digest (bytes) to a hex string to store in the set
        current_hash = hash_function(item.encode()).hex()
        if current_hash in hashes_seen:
            collisions_found += 1
            print(f"  -  COLLISION FOUND! Hash: {current_hash}")
        else:
            hashes_seen.add(current_hash)

    if collisions_found == 0:
        print("  - No collisions were found.")
    return collisions_found


def main():
    """
    Analyzes and compares the performance of MD5, SHA-1, and SHA-256.
    """
    num_strings = 100  # Dataset size as per the prompt
    print(f"Starting performance analysis for hashing algorithms...")
    print(f"Generating a dataset of {num_strings} random strings...")
    dataset = generate_random_strings(num_strings)
    print("Dataset generated.\n")

    hash_algorithms = {
        "MD5": md5_hash,
        "SHA-1": sha1_hash,
        "SHA-256": sha256_hash
    }

    # --- Part 1: Computation Time Analysis ---
    print("--- ⏱  Computation Time Analysis ---")
    print(f"Hashing {num_strings} strings with each algorithm...")
    for name, func in hash_algorithms.items():
        time_taken = measure_hash_time(func, dataset)
        print(f"  - {name:<8}: {time_taken:.6f} seconds")

    # --- Part 2: Collision Resistance Analysis ---
    print("\n---  Collision Resistance Analysis ---")
    print("Note: Finding a collision with this small dataset is statistically impossible for these algorithms.")
    for name, func in hash_algorithms.items():
        print(f"Checking for collisions using {name}...")
        find_collisions(func, dataset)


if __name__ == "__main__":
    main()
