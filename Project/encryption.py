import Crypto
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def encrypt_symmetric(data, key):
    """
    Encrypts data symmetrically using AES encryption with a given key.

    :param data: The data to encrypt.
    :type data: bytes
    :param key: The symmetric encryption key.
    :type key: bytes
    :return: The encrypted data.
    :rtype: bytes
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext + tag

def decrypt_symmetric(encrypted_data, key):
    """
    Decrypts symmetrically encrypted data using AES decryption with a given key.

    :param encrypted_data: The encrypted data.
    :type encrypted_data: bytes
    :param key: The symmetric decryption key.
    :type key: bytes
    :return: The decrypted data.
    :rtype: bytes
    """
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.decrypt_and_verify(encrypted_data[:-16], encrypted_data[-16:])

def generate_key_pair():
    """
    Generates a pair of RSA public and private keys.

    :return: The RSA public and private keys.
    :rtype: tuple
    """
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator) 
    return key, key.publickey()

def encrypt_rsa(message, public_key):
    """
    Encrypts data using RSA encryption with a given public key.

    :param message: The data to encrypt.
    :type message: bytes
    :param public_key: The RSA public key.
    :type public_key: RSA.RsaKey
    :return: The encrypted data.
    :rtype: bytes
    """
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(message)

def decrypt_rsa(data, private_key):
    """
    Decrypts RSA encrypted data using a given private key.

    :param data: The encrypted data.
    :type data: bytes
    :param private_key: The RSA private key.
    :type private_key: RSA.RsaKey
    :return: The decrypted data.
    :rtype: bytes
    """
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(data)

def decrypt_rsa_in_chunks(ciphertext, private_key, chunk_size=256):
    """
    Decrypts RSA encrypted data in chunks using a given private key.

    :param ciphertext: The encrypted data.
    :type ciphertext: bytes
    :param private_key: The RSA private key.
    :type private_key: RSA.RsaKey
    :param chunk_size: The size of each decryption chunk in bytes.
    :type chunk_size: int
    :return: The decrypted data.
    :rtype: bytes
    """
    try:
        cipher = PKCS1_OAEP.new(private_key)
        if not isinstance(ciphertext, bytes):
            raise ValueError("Ciphertext must be a byte array")
        if not isinstance(private_key, RSA.RsaKey):
            raise ValueError("Private key must be an RSA private key object")
        decrypted_message = b""
        for i in range(0, len(ciphertext), chunk_size):
            chunk = ciphertext[i:min(i + chunk_size, len(ciphertext))]
            if len(chunk) < chunk_size:
                continue
            decrypted_chunk = cipher.decrypt(chunk)
            decrypted_message += decrypted_chunk
        return decrypted_message
    except Exception as e:
        print(f"Error: {str(e)}")
        return None
