# qp.py

from helper import *
import hashlib
import time
import os

#dictinory:prescription and patient data
#diffe hellman key process

# --- Main hospital_management_system. ---

class Hospital_management:
    def __init__(self):
        self.hill_key = [[3,3],[2,7]]
        self.patient_data = []
        self.precription = []
        self.p, self.g = dh_params()
        self.a, self.A = dh_keypair(self.p, self.g)
        self.b, self.B = dh_keypair(self.p, self.g)
        self.shared_key = dh_shared(self.p, self.b, self.A)
        self.key16=b"0123456789ABCDEF"
        self.msg_hash = None
        # RSA
        self.prv, self.pub = rsa_key()



    def patient(self):
        print("\n--- patient Menu ---")
        details = input("Enter your details (e.g., 'p001,alice,fever&cough'): ")
        detailst = [i for i in details.split(',')]

        hills = hill_all(details,self.hill_key)
        hill_ct = hills.encrypt()
        print('hill cipher text is: ',hill_ct)
        # AES-CBC
        iv = get_random_bytes(16)
        ct = aes_cbc_enc(hill_ct.encode(), self.key16, iv)
        print("\nAES-CBC-256 Enc:", ct.hex())
        #print("AES-CBC dec:", aes_cbc_dec(ct, self.key16, iv).decode())
        patient_shared_key = dh_shared(self.p, self.a, self.B)
        print("diffe hellman private key for patient: ",self.a)
        print("diffe hellman public key for patient: ",self.A)
        print("diffe hellman shared key for patient: ",patient_shared_key)
        #nurse_shared_key = dh_shared(p, b, A)
        print("patient shared data successfully to nurse\n\n")

        data = {'pid':detailst[0], 'name':detailst[1], 'symptoms':detailst[2],'processed':False,'ct':ct,'iv':iv,'docprocessed':False}

        self.patient_data.append(data)
    def nurse(self):
        nurse_shared_key = dh_shared(self.p,self.b, self.A)
        if nurse_shared_key == nurse_shared_key:
            print('valid diffe hellman key')
        else:
            print('invalid diffe hellman key')
            return
        for i in self.patient_data:
            if i['processed'] == False:
                aes_ct = aes_cbc_dec(i['ct'], self.key16, i['iv']).decode()
                print('aes intermediate: ',aes_ct)
                hill = hill_all(aes_ct,self.hill_key)
                ct = hill.decrypt(aes_ct,self.hill_key)
                print('final ct: ',ct)
                i['processed'] = True

    def doctor(self):
        print('reviewing\n')
        for i in self.patient_data:
            if i['processed'] == True:
                print(i['pid'],i['name'],i['symptoms'])
                i['docprocessed'] = True
                print('enter precrisption: ')
                pri = input("pri: ")
                prilst = [i for i in pri.split(',')]
                print(prilst)
                self.msg_hash = hashlib.sha512(pri.encode()).digest()
                print(self.msg_hash)
                ct = rsa_enc(pri.encode(), self.pub)
                print("RSA Enc:", ct.hex())
                data = {'pid':pri[0],'med':pri[1],'dosage':pri[2],'hash':self.msg_hash,'ct' :ct}
                self.precription.append(data)

    def pharma(self):
        for i in self.precription:

            print("RSA Dec:", rsa_dec(i['ct'], self.prv).decode())
            ct = rsa_dec(i['ct'], self.prv).decode()
            msg_hash1 = hashlib.sha512(ct.encode()).digest()
            if msg_hash1 == i['hash']:
                print('True')
            else:
                print('False')
















def main():
    hosp = Hospital_management()

    while True:
        print("\n==============================")
        print("  hospital management Menu")
        print("==============================")
        print("1. Act as patient (enter patient record)")
        print("2. Act as nurse (Process Transactions)")
        print("3. Act as doctor (Review Transactions)")
        print("4. Act as pharmacist (Review Transactions)")
        print("5. Exit")
        choice = input("Choose your role: ")

        if choice == '1':
            hosp.patient()
        elif choice == '2':
            hosp.nurse()
        elif choice == '3':
            hosp.doctor()
        elif choice == '4':
            hosp.pharma()
        elif choice == '5':
            print("Exiting system.")
            break
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()