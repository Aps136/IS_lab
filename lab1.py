from helper import *

#q1

message = 'I am learning information securoty'
print('-'*100)

ceasure = add(message,20)
ct = ceasure.encrypt()
print(ct)
pt = ceasure.decrypt(ct)
print(pt)


multi = mul(message,15)
ct = multi.encrypt()
print(ct)
pt = multi.decrypt(ct)
print(pt)


aff = affine(message,15,20)
ct = aff.encrypt()
print(ct)
pt = aff.decrypt(ct)
print(pt);print('-'*100)

#q2
message = 'the house is being sold tonight'
v = vigenere(message,'DOLLARS')
ct = v.encrypt()
pt = v.decrypt(ct)
print(ct,pt,sep = '\n')

message = 'the house is being sold tonight'
v = autokey(message,7)
ct = v.encrypt()
pt = v.decrypt(ct)
print(ct,pt,sep = '\n')
print('-'*100)


#q3
message = 'The key is hidden under the door pad'
v = playfair()
key = v.generate_key()
ct = v.encrypt(message,key)
pt = v.decrypt(ct,key)
print(ct,pt,sep = '\n')

print('-'*100)
#4
message = 'We live in an insecure world'
key = [[3,3],[2,7]]
v = hill_all(message,key)
ct = v.encrypt()
pt = v.decrypt(ct)
print(ct,pt,sep = '\n')
print('-'*100)


print(ceasure.decrypt('XVIEWYWI',4))

clean   = lambda s: "".join(c for c in s.upper() if c.isalpha())
toZ26   = lambda s: [A.index(c) for c in s]
fromZ26 = lambda v: "".join(A[i % 26] for i in v)
modinv = lambda a, m: pow(a, -1, m)
A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def affine_enc(pt, a, b): return fromZ26([(a * x + b) % 26 for x in toZ26(clean(pt))])
def affine_dec(ct, a, b): return fromZ26([(modinv(a, 26) * (x - b)) % 26 for x in toZ26(clean(ct))])
key=None
for i in range(1,26):
    for j in range(1,26):
        try:
            a = affine_enc('AB',i,j)
            if a  == 'GL':
                key = (i,j)
                break
        except:
            pass
print(key)
print(affine_dec('GL',key[0],key[1]))
print(affine_dec('XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS',key[0],key[1]))
