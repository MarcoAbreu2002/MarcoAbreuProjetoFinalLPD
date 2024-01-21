import Crypto
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def encrypt_symmetric(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext + tag

def decrypt_symmetric(encrypted_data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.decrypt_and_verify(encrypted_data[:-16], encrypted_data[-16:])

def generate_key_pair():
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator) 
    return key, key.publickey()

def encrypt_rsa(message, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(message)

def decrypt_rsa(data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(data)

def decrypt_rsa_in_chunks(ciphertext, private_key, chunk_size=256):
    try:
        # Create a cipher object with the provided private key
        cipher = PKCS1_OAEP.new(private_key)

        # Initialize an empty byte array to store the decrypted message
        decrypted_message = b''
        print("size: " + str(len(ciphertext)))
        # Iterate over chunks of ciphertext and decrypt each chunk
        for i in range(0, len(ciphertext), chunk_size):
            print("i: " + str(i))
            chunk = ciphertext[i:min(i + chunk_size, len(ciphertext))]
            print("chunk: ")
            # Decrypt the chunk and append to the decrypted message
            decrypted_chunk = cipher.decrypt(chunk)
            print("decrypt: " + decrypted_chunk.decode('utf-8'))
            decrypted_message += decrypted_chunk

        return decrypted_message

    except Exception as e:
        # Handle cryptographic exceptions
        print(f"Error during RSA decryption: {e}")
        return None
