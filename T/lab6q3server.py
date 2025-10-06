import socket
import json
from base64 import b64decode
from helper import dh_params, dh_keypair, dh_shared, aes_cbc_dec
from lab6 import schnorr_verify # Re-use our Schnorr implementation

def main():
    HOST = '127.0.0.1'
    PORT = 65434

    # 1. Server's long-term setup
    print("--- Secure Server ---")
    p, g = dh_params(256)
    server_dh_private, server_dh_public = dh_keypair(p, g)
    print("Generated DH parameters and server keypair.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"✅ Server listening on {HOST}:{PORT}...")
        conn, addr = s.accept()

        with conn:
            print(f"🔗 Connected by {addr}")

            # 2. Exchange public keys and parameters
            # Receive client's public keys and DH parameters
            client_data = json.loads(conn.recv(2048).decode())
            client_dh_public = client_data['dh_public']
            client_schnorr_public = client_data['schnorr_public']
            p, g = client_data['p'], client_data['g']
            print("Received client public keys and DH parameters.")

            # Send server's public DH key
            conn.sendall(json.dumps({'dh_public': server_dh_public}).encode())
            print("Sent server public DH key.")

            # 3. Compute shared secret key for AES
            shared_secret = dh_shared(p, server_dh_private, client_dh_public)
            # Use the first 16 bytes of the SHA256 hash of the secret as the AES key
            aes_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]
            print("Shared secret computed.")

            # 4. Receive encrypted message and signature from client
            encrypted_payload = json.loads(conn.recv(2048).decode())
            iv = b64decode(encrypted_payload['iv'])
            ciphertext = b64decode(encrypted_payload['ciphertext'])
            signature = tuple(encrypted_payload['signature'])
            print("Received encrypted message and signature.")

            # 5. Verify signature first for authenticity
            # We verify the signature of the CIPHERTEXT to ensure its integrity
            is_valid = schnorr_verify(ciphertext, signature, p, g, client_schnorr_public)

            if is_valid:
                print("✅ Signature is VALID. Proceeding to decryption.")
                # 6. If signature is valid, decrypt the message
                decrypted_message = aes_cbc_dec(ciphertext, aes_key, iv)
                print("\n--- FINAL RESULT ---")
                print(f"Successfully decrypted message: {decrypted_message.decode()}")
            else:
                print("\n--- FINAL RESULT ---")
                print("❌ INVALID SIGNATURE! Message discarded.")

if __name__ == '__main__':
    # We need a SHA256 implementation for our AES key derivation
    import hashlib
    main()
