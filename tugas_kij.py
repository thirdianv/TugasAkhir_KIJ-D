import os, binascii
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA

key_size = 2048

# Generate public and private keys for A and V
privateKey_A = RSA.generate(key_size)
f = open('privateKey_A.pem','wb')
f.write(privateKey_A.export_key('PEM'))
f.close()

publicKey_A = privateKey_A.publickey()
f = open('publicKey_A.pem','wb')
f.write(publicKey_A.export_key('PEM'))
f.close()

privateKeyB = RSA.generate(key_size)
f = open('privateKeyB.pem','wb')
f.write(privateKeyB.export_key('PEM'))
f.close()

publicKey_B = privateKeyB.publickey()
f = open('publicKey_B.pem','wb')
f.write(publicKey_B.export_key('PEM'))
f.close()

print("1.")

N1 = os.urandom(16)
print("N1: ", binascii.hexlify(N1))

IDa = b"A"
print("IDa: ", IDa)

message1 = {
    'Identifier' : IDa,
    'Nonce_1' : N1
}

message1 = str(message1).encode('utf-8')
print("message1: ", binascii.hexlify(message1))

# encrypt
ciphB = PKCS1_OAEP.new(publicKey_B)
encrypted_message = ciphB.encrypt(message1)
print("encrypted_message : ", binascii.hexlify(encrypted_message))

# decrypt
ciphB = PKCS1_OAEP.new(privateKeyB)
decrypted_message = ciphB.decrypt(encrypted_message)
print("decrypted_message: ", binascii.hexlify(decrypted_message))
print("=========================================================================================================\n")

print("2.")
N2 = os.urandom(16)
print("N2: ", binascii.hexlify(N2))

message2 = {
    'Nonce_1' : N1,
    'Nonce_2' : N2
}

message2= str(message2).encode('utf-8')
print("message2: ", binascii.hexlify(message2))

PUa = RSA.importKey(open('publicKey_A.pem').read())
ciphA = PKCS1_OAEP.new(PUa)
encrypted_message = ciphA.encrypt(message2)
print("encrypted_message: ", binascii.hexlify(encrypted_message))

PRa = RSA.importKey(open('privateKey_A.pem').read())
ciphA = PKCS1_OAEP.new(PRa)
decrypted_message = ciphA.decrypt(encrypted_message)
print("decrypted_message: ", binascii.hexlify(decrypted_message))
print("=========================================================================================================\n")

print("3.")

message3 = {
    'Nonce_2' : N2
}

message3= str(message3).encode('utf-8')
print("message3: ", binascii.hexlify(message3))

PUb = RSA.importKey(open('publicKey_B.pem').read())
ciphB = PKCS1_OAEP.new(PUb)
encrypted_message = ciphB.encrypt(message3)
print("encrypted_message : ", binascii.hexlify(encrypted_message))

ciphB = PKCS1_OAEP.new(privateKeyB)
decrypted_message = ciphB.decrypt(encrypted_message)
print("decrypted_message: ", binascii.hexlify(decrypted_message))
print("=========================================================================================================\n")


print("4.")
Ks = os.urandom(16)
AkeB = Ks
print("Secret Key: ", binascii.hexlify(AkeB))
PRa = RSA.importKey(open('privateKey_A.pem').read())
ciphA = PKCS1_OAEP.new(PRa)
encrypted_Ks = ciphA.encrypt(AkeB)
print(len(Ks))
print(len(encrypted_Ks))
PUb = RSA.importKey(open('publicKey_B.pem').read())
ciphB = PKCS1_OAEP.new(PUb)

chunk_size = 256
chunks = [Ks[i:i+chunk_size] for i in range(0, len(Ks), chunk_size)]

encrypted_chunks = []
for chunk in chunks:
    encrypted_chunks.append(ciphB.encrypt(chunk))
encrypted_message = b''.join(encrypted_chunks)
print("encrypted_message: ", binascii.hexlify(encrypted_message))

ciphB = PKCS1_OAEP.new(privateKeyB)
decrypted_message = ciphB.decrypt(encrypted_message)
print("decrypted_message: ", binascii.hexlify(decrypted_message))
print("=========================================================================================================\n")