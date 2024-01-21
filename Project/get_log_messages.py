import getpass
import sys
from Crypto.PublicKey import RSA
from encryption import decrypt_rsa_in_chunks


def decrypt_private_key(encrypted_key_data, passphrase):
    # Decrypt the private key
    try:
        private_key = RSA.import_key(encrypted_key_data, passphrase=passphrase)
        return private_key
    except ValueError:
        # Handle incorrect password or decryption failure
        return None

def get_private_key_password(encrypted_private_key):
    password_attempts = 3
    while password_attempts > 0:
        password = getpass.getpass("Enter the private key password: ")
        decrypted_private_key = RSA.import_key(encrypted_private_key, passphrase= password)
        if decrypted_private_key is not None:
            print("Key Restored!")
            return  decrypted_private_key
        else:
            print("Incorrect password. Please try again.")
            password_attempts -= 1

    print("Maximum attempts reached. Exiting.")
    sys.exit()

def decrypt_log_messages():
    try:
        with open("server_private_key_encrypted.pem", "rb") as f:
            encrypted_private_key = f.read()

        decrypted_private_key = get_private_key_password(encrypted_private_key)

        with open("log_messages_encrypted.txt", "rb") as f:
            encrypted_messages = f.read()

        decrypted_messages = decrypt_rsa_in_chunks(encrypted_messages, decrypted_private_key)
        print("Decrypted Messages:")
        print(decrypted_messages.decode('utf-8'))

    except Exception as e:
        print(f"Error decrypting log messages: {e}")
    finally:
        decrypted_private_key = None  # Clear the decrypted private key from memory

if __name__ == "__main__":
    decrypt_log_messages()
