import hashlib
import random
import string
import time

# Generate random strings
def generate_random_strings(count=50, length=10):
    data = []
    for _ in range(count):
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        data.append(s)
    return data

# Compute hashes and measure time
def hash_performance(data, algorithm='md5'):
    hasher = getattr(hashlib, algorithm)
    start = time.time()
    hashes = [hasher(d.encode()).hexdigest() for d in data]
    end = time.time()
    duration = end - start
    return hashes, duration

# Collision detection
def detect_collisions(hashes):
    seen = set()
    collisions = []
    for h in hashes:
        if h in seen:
            collisions.append(h)
        else:
            seen.add(h)
    return collisions

if __name__ == "__main__":
    dataset = generate_random_strings(count=100, length=20)

    for algo in ['md5', 'sha1', 'sha256']:
        hashes, duration = hash_performance(dataset, algorithm=algo)
        collisions = detect_collisions(hashes)
        print(f"{algo.upper()} took {duration:.6f} seconds to hash {len(dataset)} strings.")
        if collisions:
            print(f"Collisions detected: {len(collisions)}")
        else:
            print("No collisions detected.")
        print("-" * 40)
