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

def decrypt_rsa_in_chunks(ciphertext, private_key, chunk_size=128):
    # Create a cipher object
    cipher = PKCS1_OAEP.new(private_key)
    # Initialize an empty string to store the decrypted message
    decrypted_message = b''
    # Iterate over chunks of ciphertext and decrypt each chunk
    for i in range(0, len(ciphertext), chunk_size):
        chunk = ciphertext[i:i + chunk_size]
        decrypted_chunk = cipher.decrypt(chunk)
        decrypted_message += decrypted_chunk
    return decrypted_message
