import Crypto
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def generate_key_pair():
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator) 
    return key, key.publickey()

def encrypt_rsa(message, public_key):
    print("Encrypting...")
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(message)

def decrypt_rsa(data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher_rsa.decrypt(data)
    return decrypted_data
