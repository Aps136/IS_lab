from helper import *
from Crypto.Hash import SHA256

class HospitalManagement:
    def __init__(self):
        # patient store and prescription store
        self.patient_data = []      # list of dicts: {'PID', 'Name', 'Problem'}
        self.prescriptions = []     # list of dicts: {'PID','ct','hash'}
        # Hill key (2x2 defined by you)
        self.hill_key = [[3, 3], [2, 7]]

        # DH params and keypairs (simulate patient & nurse keypairs created once)
        self.p, self.g = dh_params()          # large prime, generator
        # Patient DH keypair
        self.a, self.A = dh_keypair(self.p, self.g)
        # Nurse DH keypair
        self.b, self.B = dh_keypair(self.p, self.g)

        # Doctor and Pharmacist RSA keys
        self.pharm_prv, self.pharm_pub = rsa_key(bits=1024)   # pharmacist keypair
        # doctor doesn't need RSA keys for this workflow (doctor encrypts for pharmacist)

        print("Initialized DH params and RSA keys.")
        print(f"DH p bits: {self.p.bit_length()}, generator g: {self.g}")
        print(f"Patient pub A: {self.A}\nNurse pub B: {self.B}\n")

    # ---------- Patient: input and encrypt ----------
    def patient(self):
        print("\n--- PATIENT: Enter Data ---")
        pid = int(input("Patient ID: ").strip())
        name = input("Name: ").strip()
        disease = input("Disease: ").strip()
        manifest = f"{pid}|{name}|{disease}"
        print("Plain manifest:", manifest)

        # 1) Hill encryption (returns a string)
        hill_obj = hill_all(manifest, self.hill_key)
        hill_ct_str = hill_obj.encrypt()
        print("Hill ciphertext (string):", hill_ct_str)

        # Convert hill ciphertext string -> bytes for AES
        hill_ct_bytes = hill_ct_str.encode()

        # 2) Diffie-Hellman: patient computes shared secret with nurse's public B
        shared_patient = dh_shared(self.p, self.a, self.B)
        # Derive AES-256 key from shared secret using SHA-256
        aes_key = SHA256.new(str(shared_patient).encode()).digest()  # 32 bytes

        # 3) AES-ECB encrypt Hill ciphertext (helper's aes_ecb_enc expects bytes key length 16/24/32)
        aes_ct = aes_ecb_enc(hill_ct_bytes, aes_key)
        print("AES-256-ECB ciphertext (hex):", aes_ct.hex())

        # Store transmitted data for Nurse to receive:
        # The nurse will compute shared secret locally using its private b and patient's public A and derive same AES key
        self.buffer_patient_to_nurse = {
            "aes_ct": aes_ct,
            "patient_pub": self.A
        }

        # Add patient record (doctor will read later)
        self.patient_data.append({'PID': pid, 'Name': name, 'Problem': disease})
        print("Patient data stored and ciphertext sent to Nurse (buffer).")

    # ---------- Nurse: receive & decrypt ----------
    def nurse(self):
        print("\n--- NURSE: Receive & Decrypt ---")
        if not hasattr(self, "buffer_patient_to_nurse"):
            print("No data from patient. Please run patient() first.")
            return

        aes_ct = self.buffer_patient_to_nurse["aes_ct"]
        patient_pub = self.buffer_patient_to_nurse["patient_pub"]

        # Nurse computes the shared secret using her private key b and patient's public A
        shared_nurse = dh_shared(self.p, self.b, patient_pub)
        aes_key_nurse = SHA256.new(str(shared_nurse).encode()).digest()

        # Decrypt AES -> get hill ciphertext bytes
        try:
            hill_ct_bytes = aes_ecb_dec(aes_ct, aes_key_nurse)
        except Exception as e:
            print("AES decryption failed:", e)
            return

        hill_ct_str = hill_ct_bytes.decode()
        print("Recovered Hill ciphertext (string):", hill_ct_str)

        # Hill decrypt to original manifest
        hill_obj = hill_all('', self.hill_key)
        try:
            manifest = hill_obj.decrypt(hill_ct_str)
        except Exception as e:
            print("Hill decryption failed:", e)
            return

        print("Decrypted manifest (Patient -> Nurse):", manifest)
        # Nurse forwards manifest to Doctor buffer
        self.buffer_nurse_to_doctor = {'manifest': manifest}
        print("Manifest forwarded to Doctor (buffer).")

    # ---------- Doctor: read and create prescription ----------
    def doctor(self):
        print("\n--- DOCTOR: Read Manifests & Create Prescription ---")
        if not hasattr(self, "buffer_nurse_to_doctor"):
            print("No manifest from Nurse. Please run nurse() first.")
            return

        manifest = self.buffer_nurse_to_doctor["manifest"]
        print("Manifest for doctor:", manifest)
        # Extract PID to link prescription
        try:
            pid_str = manifest.split("|")[0]
            pid = int(pid_str)
        except Exception:
            pid = None

        presc_text = input("Enter prescription text: ").strip().encode()

        # Compute SHA-256 hash of prescription plaintext
        presc_hash = sha256_hash(presc_text)   # bytes digest
        print("Prescription SHA-256 (hex):", presc_hash.hex())

        # Encrypt prescription with Pharmacist's RSA public key
        presc_ct = rsa_enc(presc_text, self.pharm_pub)
        print("Prescription encrypted (RSA) hex:", presc_ct.hex())

        # Store prescription info for pharmacist
        self.prescriptions.append({
            'PID': pid,
            'ct': presc_ct,
            'hash': presc_hash
        })
        print("Encrypted prescription and hash sent to Pharmacist (buffer).")

    # ---------- Pharmacist: decrypt and verify ----------
    def pharmacist(self):
        print("\n--- PHARMACIST: Decrypt & Verify Prescription(s) ---")
        if not self.prescriptions:
            print("No prescriptions available. Have Doctor issue one first.")
            return

        for idx, item in enumerate(self.prescriptions, 1):
            print(f"\nPrescription #{idx} for PID: {item['PID']}")
            ct = item['ct']
            expected_hash = item['hash']
            # Decrypt with pharmacist private key
            try:
                pt = rsa_dec(ct, self.pharm_prv)
            except Exception as e:
                print("RSA decryption failed:", e)
                continue

            print("Decrypted prescription text:", pt.decode())
            computed_hash = sha256_hash(pt)
            print("Computed SHA-256 (hex):", computed_hash.hex())
            print("Doctor's SHA-256 (hex):", expected_hash.hex())
            if computed_hash == expected_hash:
                print("Hashes match: Prescription VERIFIED ✅")
            else:
                print("Hash mismatch: Prescription REJECTED ❌")

    # ---------- Utility: show stored records ----------
    def show_records(self):
        print("\n--- Stored Patients ---")
        for p in self.patient_data:
            print(p)
        print("\n--- Stored Prescriptions (encrypted) ---")
        for pr in self.prescriptions:
            print({'PID': pr['PID'], 'ct_len': len(pr['ct']), 'hash': pr['hash'].hex()})

# ---------- Menu ----------
def main_menu():
    hm = HospitalManagement()
    while True:
        print("\n===== Menu =====")
        print("1. Patient: input & encrypt (Hill -> AES via DH)")
        print("2. Nurse: receive & decrypt (AES -> Hill) and forward")
        print("3. Doctor: read manifest & create prescription (encrypt with Pharmacist RSA)")
        print("4. Pharmacist: decrypt prescription & verify hash")
        print("5. Show stored data (debug)")
        print("6. Exit")
        choice = input("Choice: ").strip()
        if choice == '1':
            hm.patient()
        elif choice == '2':
            hm.nurse()
        elif choice == '3':
            hm.doctor()
        elif choice == '4':
            hm.pharmacist()
        elif choice == '5':
            hm.show_records()
        elif choice == '6':
            print("Exiting.")
            break
        else:
            print("Invalid choice, try again.")

if __name__ == "__main__":
    main_menu()
