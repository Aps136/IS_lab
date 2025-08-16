import random

p = 229470361210452493055433428081205188660411
g = 5
x = 101
h = pow(g, x, p)

message = "Confidential Data"
m = int.from_bytes(message.encode('utf-8'), 'big')

k = random.randint(1, p - 1)

c1 = pow(g, k, p)
c2 = (m * pow(h, k, p)) % p

s = pow(c1, x, p)
s_inv = pow(s, -1, p)

decrypted_m = (c2 * s_inv) % p

decrypted_message = decrypted_m.to_bytes((decrypted_m.bit_length() + 7) // 8, 'big').decode('utf-8')

print(f"Original message as integer: {m}")
print(f"Ciphertext (c1, c2): ({c1}, {c2})")
print(f"Decrypted message as integer: {decrypted_m}")
print(f"Decrypted message as string: {decrypted_message}")
