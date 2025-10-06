import socket
import json
import os
from base64 import b64encode
from helper import dh_keypair, dh_shared, aes_cbc_enc
from lab6 import generate_schnorr_params, schnorr_keygen, schnorr_sign


def main():
    HOST = '127.0.0.1'
    PORT = 65434

    print("--- Secure Client ---")

    # 1. Generate public parameters and all necessary keys for the client
    p, q, g = generate_schnorr_params()  # Use Schnorr params for DH as well
    client_dh_private, client_dh_public = dh_keypair(p, g)
    client_schnorr_private, client_schnorr_public = schnorr_keygen(p, q, g)
    print("Generated DH and Schnorr keypairs.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"🔗 Connected to server at {HOST}:{PORT}")

        # 2. Send public keys and parameters to server
        public_data = {
            'p': p, 'g': g,
            'dh_public': client_dh_public,
            'schnorr_public': client_schnorr_public
        }
        s.sendall(json.dumps(public_data).encode())
        print("Sent public keys and DH parameters to server.")

        # Receive server's public DH key
        server_data = json.loads(s.recv(1024).decode())
        server_dh_public = server_data['dh_public']
        print("Received server's public DH key.")

        # 3. Compute shared secret key
        shared_secret = dh_shared(p, client_dh_private, server_dh_public)
        aes_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]
        print("Shared secret computed.")

        # 4. Prepare and encrypt the message with AES
        message_to_send = b"This is a confidential and authenticated message."
        iv = os.urandom(16)
        ciphertext = aes_cbc_enc(message_to_send, aes_key, iv)
        print(f"Encrypting message: {message_to_send.decode()}")

        # 5. Sign the ENCRYPTED message (ciphertext) with Schnorr
        signature = schnorr_sign(ciphertext, p, q, g, client_schnorr_private)
        print("Signed the encrypted ciphertext.")

        # 6. Send the encrypted payload and signature to the server
        encrypted_payload = {
            'iv': b64encode(iv).decode('utf-8'),
            'ciphertext': b64encode(ciphertext).decode('utf-8'),
            'signature': signature
        }
        s.sendall(json.dumps(encrypted_payload).encode())
        print("Sent encrypted payload and signature to server.")
        print("\nClient finished.")


if __name__ == '__main__':
    import hashlib

    main()
