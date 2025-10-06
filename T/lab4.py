from helper import *
import time
from datetime import datetime, timedelta

# ==============================================================================
# --- Question 1: SecureCorp Enterprise Communication System ---
# ==============================================================================
print("--- Question 1: SecureCorp Communication System ---")


class KeyManager:
    """
    A centralized server to manage the long-term RSA keys for all subsystems.
    In a real system, this would be a highly secure, trusted authority.
    """

    def __init__(self):
        self._public_keys = {}
        self._revoked_keys = set()
        print("[KM] Key Manager initialized.")
        # FIX: Generate DH parameters once for the whole enterprise
        print("[KM] Generating enterprise-wide DH parameters...")
        self.dh_p, self.dh_g = dh_params(bits=512)

    def generate_rsa_keys(self, subsystem_id, bits=2048):
        """Generates RSA key pair for a subsystem and stores its public key."""
        private_key, public_key = rsa_key(bits)
        self._public_keys[subsystem_id] = public_key
        print(f"[KM] Generated and stored public key for '{subsystem_id}'.")
        return private_key

    def get_public_key(self, subsystem_id):
        """Provides the public key of a subsystem if it's not revoked."""
        if subsystem_id in self._revoked_keys:
            print(f"[KM] Access denied: Key for '{subsystem_id}' has been revoked.")
            return None
        return self._public_keys.get(subsystem_id)

    def revoke_key(self, subsystem_id):
        """Revokes a subsystem's key."""
        self._revoked_keys.add(subsystem_id)
        print(f"[KM] Revoked key for '{subsystem_id}'.")


class Subsystem:
    """
    Represents a business unit (e.g., Finance, HR) that needs to communicate securely.
    """

    def __init__(self, name, key_manager):
        self.name = name
        self.key_manager = key_manager
        # Generate and securely store its long-term RSA private key
        self._private_key = self.key_manager.generate_rsa_keys(self.name)
        # FIX: Use the shared, enterprise-wide DH parameters from the Key Manager
        self._p = self.key_manager.dh_p
        self._g = self.key_manager.dh_g
        self._shared_secrets = {}

    def initiate_key_exchange(self, recipient_id):
        """
        Starts the authenticated Diffie-Hellman key exchange to establish a shared secret.
        """
        print(f"\n[{self.name}] Initiating secure channel with '{recipient_id}'...")
        # 1. Generate ephemeral DH key pair (a, A)
        self._dh_private, self._dh_public = dh_keypair(self._p, self._g)

        # 2. Sign the DH public key with our long-term RSA private key for authentication
        dh_public_bytes = str(self._dh_public).encode()
        signature = rsa_sign(dh_public_bytes, self._private_key)
        print(f"[{self.name}] Generated and signed my DH public key.")

        # 3. "Send" our DH public key and signature to the recipient
        return self._dh_public, signature

    def respond_to_key_exchange(self, sender_id, sender_dh_public, signature):
        """Responds to an incoming key exchange request."""
        print(f"[{self.name}] Received channel request from '{sender_id}'.")
        # 1. Get the sender's public key from the trusted Key Manager
        sender_public_key = self.key_manager.get_public_key(sender_id)
        if not sender_public_key:
            print(f"[{self.name}] Could not verify '{sender_id}'. Aborting.")
            return None, False

        # 2. Verify the signature on their DH public key
        sender_dh_public_bytes = str(sender_dh_public).encode()
        is_valid = rsa_verify(sender_dh_public_bytes, signature, sender_public_key)

        if not is_valid:
            print(f"[{self.name}] Invalid signature from '{sender_id}'. Aborting.")
            return None, False

        print(f"[{self.name}] Signature from '{sender_id}' is valid.")

        # 3. Generate our own DH key pair (b, B)
        self._dh_private, self._dh_public = dh_keypair(self._p, self._g)

        # 4. Compute the shared secret
        shared_secret = dh_shared(self._p, self._dh_private, sender_dh_public)
        self._shared_secrets[sender_id] = shared_secret
        print(f"[{self.name}] Shared secret with '{sender_id}' established.")

        # 5. "Send" back our DH public key
        return self._dh_public, True

    def complete_key_exchange(self, recipient_id, recipient_dh_public):
        """Final step for the initiator to compute the shared secret."""
        shared_secret = dh_shared(self._p, self._dh_private, recipient_dh_public)
        self._shared_secrets[recipient_id] = shared_secret
        print(f"[{self.name}] Shared secret with '{recipient_id}' established.")

    def send_secure_message(self, recipient_id, message: str):
        """Encrypts a message using the established shared secret (used as an AES key)."""
        secret = self._shared_secrets.get(recipient_id)
        if not secret:
            return "Error: No secure channel established."

        aes_key = SHA256.new(str(secret).encode()).digest()
        iv = get_random_bytes(16)
        encrypted_message = aes_cbc_enc(message.encode(), aes_key, iv)
        return iv + encrypted_message

    def receive_secure_message(self, sender_id, data: bytes):
        """Decrypts a message."""
        secret = self._shared_secrets.get(sender_id)
        if not secret:
            return "Error: No secure channel."

        aes_key = SHA256.new(str(secret).encode()).digest()
        iv = data[:16]
        ciphertext = data[16:]
        decrypted_message = aes_cbc_dec(ciphertext, aes_key, iv).decode()
        return decrypted_message


# --- Simulation for Q1 ---
# Setup
km = KeyManager()
system_a = Subsystem("Finance", km)
system_b = Subsystem("HR", km)
system_c = Subsystem("SupplyChain", km)

# A. Finance establishes a secure channel with SupplyChain
dh_pub_a, sig_a = system_a.initiate_key_exchange("SupplyChain")
dh_pub_c, is_valid_response = system_c.respond_to_key_exchange("Finance", dh_pub_a, sig_a)
if is_valid_response:
    system_a.complete_key_exchange("SupplyChain", dh_pub_c)

    # B. Use the secure channel to send a message
    original_msg = "Procurement order PO-12345 approved."
    print(f"\n[{system_a.name}] Sending message: '{original_msg}'")
    encrypted_data = system_a.send_secure_message("SupplyChain", original_msg)

    decrypted_msg = system_c.receive_secure_message("Finance", encrypted_data)
    print(f"[{system_c.name}] Received and decrypted message: '{decrypted_msg}'")
    assert original_msg == decrypted_msg
    print("✅ Communication successful!")

# C. Demonstrate Key Revocation
print("\n--- Demonstrating Key Revocation ---")
km.revoke_key("Finance")
# HR now tries to connect to the revoked Finance system
dh_pub_b, sig_b = system_b.initiate_key_exchange("Finance")
# This will fail because the key manager will not provide Finance's public key
system_a.respond_to_key_exchange("HR", dh_pub_b, sig_b)
print("-" * 50, "\n")

# ==============================================================================
# --- Question 2: HealthCare Inc. Rabin Key Management Service ---
# ==============================================================================
print("--- Question 2: HealthCare Inc. Rabin Key Management Service ---")


class RabinKeyManagementService:
    """
    A centralized service to manage the lifecycle of Rabin keys for healthcare facilities.
    This service ensures compliance and maintains security through logging and automation.
    """

    def __init__(self, key_size=1024):
        self._key_size = key_size
        self._active_keys = {}  # In reality: a secure, encrypted database or HSM
        self._log = []
        self._log_event("Key Management Service Initialized.")

    def _log_event(self, message):
        """Appends a timestamped event to the audit log."""
        self._log.append(f"[{datetime.now()}] {message}")

    def generate_key_pair(self, facility_id):
        """Generates and securely stores a new Rabin key pair for a facility."""
        if facility_id in self._active_keys:
            self._log_event(f"ERROR: Key generation failed. '{facility_id}' already exists.")
            return
        n, p, q = rabin_key(self._key_size)
        self._active_keys[facility_id] = {
            'public_key': n,
            'private_key': (p, q),
            'creation_date': datetime.now()
        }
        self._log_event(f"Generated new key pair for '{facility_id}'.")

    def distribute_keys(self, facility_id):
        """Simulates a secure API to provide a facility with its keys."""
        key_info = self._active_keys.get(facility_id)
        if key_info:
            self._log_event(f"Distributed keys to '{facility_id}' over a secure channel.")
            return key_info['public_key'], key_info['private_key']
        self._log_event(f"ERROR: Key distribution failed for non-existent '{facility_id}'.")
        return None, None

    def revoke_key(self, facility_id, reason="compromise"):
        """Revokes a key, for example, due to a security breach."""
        if facility_id in self._active_keys:
            del self._active_keys[facility_id]
            self._log_event(f"Revoked key for '{facility_id}' due to: {reason}.")
        else:
            self._log_event(f"ERROR: Revocation failed for non-existent '{facility_id}'.")

    def renew_all_keys(self, renewal_period_days=365):
        """Automatically renews keys that have expired."""
        self._log_event("Starting scheduled key renewal process...")
        now = datetime.now()
        facilities_to_renew = []
        for facility_id, key_info in self._active_keys.items():
            if now - key_info['creation_date'] > timedelta(days=renewal_period_days):
                facilities_to_renew.append(facility_id)

        for facility_id in facilities_to_renew:
            self._log_event(f"Key for '{facility_id}' has expired. Renewing...")
            self.revoke_key(facility_id, reason="scheduled renewal")
            self.generate_key_pair(facility_id)

    def show_logs(self):
        print("\n--- Audit and Logging Report ---")
        for entry in self._log:
            print(entry)
        print("--- End of Report ---")


# --- Simulation for Q2 ---
kms = RabinKeyManagementService(key_size=512)  # Using smaller key for speed

# Key Generation
kms.generate_key_pair("Hospital-A")
kms.generate_key_pair("Clinic-B")

# Key Distribution
pub_a, priv_a = kms.distribute_keys("Hospital-A")
n_a = pub_a
p_a, q_a = priv_a

# Demonstrate Encryption/Decryption
patient_record = b"Patient ID: 12345, Diagnosis: Stable"
# Convert message to integer for Rabin encryption
msg_int = int.from_bytes(patient_record, 'big')
ciphertext = rabin_enc(msg_int, n_a)
print(f"\nOriginal Record: {patient_record.decode()}")
print(f"Encrypted Record (as integer): {ciphertext}")

# Decryption yields 4 results; we must find the correct one
possible_plaintexts = rabin_dec(ciphertext, n_a, p_a, q_a)
decrypted_record = b''
for pt_int in possible_plaintexts:
    try:
        pt_bytes = pt_int.to_bytes((pt_int.bit_length() + 7) // 8, 'big')
        if pt_bytes.startswith(b'Patient ID'):  # Simple check to find the right message
            decrypted_record = pt_bytes
            break
    except Exception:
        continue
print(f"Decrypted Record: {decrypted_record.decode()}")
assert patient_record == decrypted_record
print("✅ Rabin encryption/decryption successful!")

# Key Revocation
kms.revoke_key("Clinic-B", reason="Facility closed")

# Key Renewal (simulating that Hospital-A's key is old)
kms._active_keys["Hospital-A"]['creation_date'] = datetime.now() - timedelta(days=400)
kms.renew_all_keys()

# Auditing and Logging
kms.show_logs()
print("-" * 50, "\n")

# --- Trade-off Analysis: Rabin vs. RSA ---
print("--- Trade-off Analysis: Rabin vs. RSA ---")
print("""
**Rabin Cryptosystem**

* **Strengths:**
    * ✅ **Provable Security:** Its security is mathematically proven to be as difficult as factoring its modulus `n`. This is a very strong security guarantee that RSA lacks.
    * 🚀 **Fast Encryption:** The encryption process is extremely efficient, requiring only a single modular squaring operation, making it much faster than RSA's modular exponentiation.

* **Weaknesses:**
    * 🤔 **Decryption Ambiguity:** Decryption produces four possible plaintexts for every ciphertext. The correct one must be identified, which adds complexity and slight overhead to the decryption process.
    * ⚠️ **Vulnerable to Chosen-Ciphertext Attack (CCA):** Without proper padding, Rabin is completely vulnerable to a CCA, where an attacker who can trick the system into decrypting chosen ciphertexts can use the results to factor `n` and break the system. This makes secure implementation challenging.

**RSA Cryptosystem**

* **Strengths:**
    * 👍 **Unambiguous Decryption:** Decryption yields a single, correct plaintext, which greatly simplifies its implementation and use.
    * 🌐 **Industry Standard:** RSA is widely adopted, standardized (PKCS#1), and supported by robust, well-vetted libraries. Standardized padding schemes (like OAEP) make it secure against common attacks.

* **Weaknesses:**
    * 🔒 **No Provable Security Equivalence:** Its security is *related* to the difficulty of factoring, but it has not been proven to be equivalent. It's theoretically possible (though unlikely) that a method exists to break RSA without factoring `n`.
    * 🐢 **Slower Operations:** Both encryption and decryption involve modular exponentiation, which is more computationally intensive than Rabin's encryption.

**Conclusion:**
While Rabin is theoretically elegant and faster for encryption, its practical drawbacks—decryption ambiguity and severe vulnerability to chosen-ciphertext attacks—make it difficult to implement securely. For this reason, **RSA, with standardized padding schemes, is the overwhelmingly preferred choice** for most real-world applications due to its simplicity, robustness, and widespread trust.
""")
