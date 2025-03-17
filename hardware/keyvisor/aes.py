# Python Code to check the results from the KeyVisor hardware implementation.
# Unless you modify KeyVisor, you will probably not need this code.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii

def encrypt(plaintext, key, nonce, aad):
    aesgcm = AESGCM(key)
    cipher_text = aesgcm.encrypt(nonce, plaintext, aad)
    #print(f"Tag: {aesgcm.tag}")
    return cipher_text

def decrypt(ciphertext, key, nonce, aad):
    aesgcm = AESGCM(key)
    plain_text = aesgcm.decrypt(nonce, ciphertext, aad)
    return plain_text

# Example usage
key = binascii.unhexlify('acb0821d714fa2a6d2eda68e1e6f2753')
nonce = binascii.unhexlify('6b3539230000000000000001')
aad = binascii.unhexlify('00000000000000011703030012')
plaintext = binascii.unhexlify('407b44bc766729aba6ac651dfb6b68944815')

# Encryption
ciphertext = encrypt(plaintext, key, nonce, aad)
ct = ciphertext.hex()
print(f"Enc {ct[:-32]}")
print(f"Tag {ct[-32:]}")
#print("Ciphertext:", ciphertext.hex())

# Decryption
decrypted_text = decrypt(ciphertext, key, nonce, aad)
print("Decrypted text:", decrypted_text.hex())