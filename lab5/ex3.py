import hashlib
import random
import string
import time

# Function to generate random strings
def generate_random_strings(n, length=10):
    dataset = []
    for _ in range(n):
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        dataset.append(s)
    return dataset

# Function to compute hashes and measure time
def compute_hashes(dataset, algo_name):
    start = time.time()
    hashes = []
    for s in dataset:
        if algo_name == "md5":
            h = hashlib.md5(s.encode()).hexdigest()
        elif algo_name == "sha1":
            h = hashlib.sha1(s.encode()).hexdigest()
        elif algo_name == "sha256":
            h = hashlib.sha256(s.encode()).hexdigest()
        hashes.append(h)
    end = time.time()
    return hashes, (end - start)

# Function to detect collisions
def detect_collisions(hashes):
    seen = {}
    collisions = []
    for i, h in enumerate(hashes):
        if h in seen:
            collisions.append((seen[h], i))  # store indices of colliding strings
        else:
            seen[h] = i
    return collisions

# -------------------------
# Main experiment
dataset = generate_random_strings(random.randint(50, 100), length=15)
print(f"Generated dataset size: {len(dataset)} strings\n")

for algo in ["md5", "sha1", "sha256"]:
    hashes, duration = compute_hashes(dataset, algo)
    collisions = detect_collisions(hashes)
    print(f"Algorithm: {algo.upper()}")
    print(f" Time taken: {duration:.6f} seconds")
    print(f" Unique hashes: {len(set(hashes))}")
    print(f" Collisions found: {len(collisions)}\n")
