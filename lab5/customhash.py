def chash(s):
    h = 5381
    for ch in s:
        h = (h * 33) + ord(ch)
        h = h & 0xFFFFFFFF
    return h
text = "HashExample"
hash_value = chash(text)
print(f"Input: {text}")
print(f"Hash value: {hash_value}")
