import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

message = b"Performance Testing of Encryption Algorithms"

des_secret_key = b"A1B2C3D4!"
aes_secret_key = b"0123456789abcdef0123456789abcdef0123456789abcdef"

number_of_runs = 10000

def measure_crypto_performance(algorithm, key, data_to_process, runs):
    start_time_encrypt = time.perf_counter()
    for _ in range(runs):
        cipher_encrypt = algorithm.new(key, algorithm.MODE_ECB)
        padded_data = pad(data_to_process, algorithm.block_size)
        ciphertext = cipher_encrypt.encrypt(padded_data)
    end_time_encrypt = time.perf_counter()
    total_encryption_time_ms = (end_time_encrypt - start_time_encrypt) * 1000
    start_time_decrypt = time.perf_counter()
    for _ in range(runs):
        cipher_decrypt = algorithm.new(key, algorithm.MODE_ECB)
        decrypted_padded_data = cipher_decrypt.decrypt(ciphertext)
        original_data = unpad(decrypted_padded_data, algorithm.block_size)
    end_time_decrypt = time.perf_counter()
    total_decryption_time_ms = (end_time_decrypt - start_time_decrypt) * 1000
    return total_encryption_time_ms, total_decryption_time_ms

print("--- DES Encryption/Decryption Test ---")
des_enc_time, des_dec_time = measure_crypto_performance(DES, des_secret_key, message, number_of_runs)
print(f"DES Total Encryption Time ({number_of_runs} runs): {des_enc_time:.4f} milliseconds")
print(f"DES Total Decryption Time ({number_of_runs} runs): {des_dec_time:.4f} milliseconds")
print("-" * 40)

print("--- AES-256 Encryption/Decryption Test ---")
aes_enc_time, aes_dec_time = measure_crypto_performance(AES, aes_secret_key, message, number_of_runs)
print(f"AES-256 Total Encryption Time ({number_of_runs} runs): {aes_enc_time:.4f} milliseconds")
print(f"AES-256 Total Decryption Time ({number_of_runs} runs): {aes_dec_time:.4f} milliseconds")
print("-" * 40)

print("\n--- Summary of Findings ---")
print(f"Message Length: {len(message)} bytes")
print(f"Number of Test Runs: {number_of_runs}")
print("\nAES-256 is generally **faster** and **more secure** than DES.")

if aes_enc_time < des_enc_time:
    print(f"AES-256 encryption was **{des_enc_time / aes_enc_time:.2f} times faster** than DES encryption.")
else:
    print(f"DES encryption was **{aes_enc_time / des_enc_time:.2f} times faster** than AES-256 encryption. (This is highly unusual!)")

if aes_dec_time < des_dec_time:
    print(f"AES-256 decryption was **{des_dec_time / aes_dec_time:.2f} times faster** than DES decryption.")
else:
    print(f"DES decryption was **{aes_dec_time / aes_dec_time:.2f} times faster** than AES-256 decryption. (This is highly unusual!)")
