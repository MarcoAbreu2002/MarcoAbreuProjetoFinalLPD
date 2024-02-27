import signal
import sqlite3
import getpass
import sys
from Crypto.PublicKey import RSA
from encryption import decrypt_rsa_in_chunks

def decrypt_private_key(encrypted_key_data, passphrase):
    """
    Decrypts the private key using the provided passphrase.

    Args:
        encrypted_key_data (bytes): The encrypted private key data.
        passphrase (str): The passphrase used for decryption.

    Returns:
        RSA.RsaKey or None: The decrypted private key if successful, None otherwise.
    """
    try:
        private_key = RSA.import_key(encrypted_key_data, passphrase=passphrase)
        return private_key
    except ValueError:
        # Handle incorrect password or decryption failure
        return None

def get_private_key_password(encrypted_private_key):
    """
    Prompts the user for the private key password and attempts to decrypt the private key.

    Args:
        encrypted_private_key (bytes): The encrypted private key data.

    Returns:
        RSA.RsaKey: The decrypted private key if successful.
    """
    password_attempts = 3
    while password_attempts > 0:
        password = getpass.getpass("Enter the private key password: ")
        decrypted_private_key = RSA.import_key(encrypted_private_key, passphrase=password)
        if decrypted_private_key is not None:
            print("Key Restored!")
            return decrypted_private_key
        else:
            print("Incorrect password. Please try again.")
            password_attempts -= 1

    print("Maximum attempts reached. Exiting.")
    sys.exit()

def decrypt_log_messages():
    """
    Decrypts log messages stored in a SQLite database using an encrypted private key.

    """
    try:
        # Read the encrypted private key from file
        with open("server_private_key_encrypted.pem", "rb") as f:
            encrypted_private_key = f.read()

        # Decrypt the private key
        decrypted_private_key = get_private_key_password(encrypted_private_key)

        # Connect to the SQLite database
        with sqlite3.connect('MESI_LPD.db') as conn:
            cursor = conn.cursor()

            # Retrieve the encrypted messages from the 'messages' table
            cursor.execute("SELECT data FROM messages")
            encrypted_messages = cursor.fetchall()

            # Decrypt and print the messages
            for encrypted_data in encrypted_messages:
                decrypted_messages = decrypt_rsa_in_chunks(encrypted_data[0], decrypted_private_key)
                if decrypted_messages is not None:
                    print(decrypted_messages.decode('utf-8'))

        # Use an infinite loop to keep the program running
        while True:
            pass

    except FileNotFoundError as fnfe:
        print(f"Private key file not found: {fnfe}")
    except sqlite3.Error as sqle:
        print(f"SQLite error: {sqle}")
    except Exception as e:
        print(f"Error decrypting log messages: {e}")
    finally:
        # Close the cursor and connection
        cursor.close()

if __name__ == "__main__":
    decrypt_log_messages()
