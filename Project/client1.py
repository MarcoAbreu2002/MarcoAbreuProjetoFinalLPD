import os
import time
import sys
import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from integrity import generate_digest, verify_digest
from encryption import generate_key_pair, encrypt_rsa, decrypt_rsa, decrypt_rsa_in_chunks

def encrypt_private_key(private_key, passphrase):
    """
    Encrypts a private key using a passphrase.

    :param private_key: The private key to encrypt.
    :type private_key: RSA.RsaKey
    :param passphrase: The passphrase to encrypt the private key.
    :type passphrase: str
    :return: The encrypted private key.
    :rtype: bytes
    """
    encrypted_key = private_key.export_key(passphrase=passphrase, pkcs=8, protection="scryptAndAES128-CBC")
    return encrypted_key

def decrypt_private_key(encrypted_key_data, passphrase):
    """
    Decrypts an encrypted private key using a passphrase.

    :param encrypted_key_data: The encrypted private key data.
    :type encrypted_key_data: bytes
    :param passphrase: The passphrase to decrypt the private key.
    :type passphrase: str
    :return: The decrypted private key or None if decryption fails.
    :rtype: RSA.RsaKey or None
    """
    try:
        private_key = RSA.import_key(encrypted_key_data, passphrase=passphrase)
        return private_key
    except ValueError:
        # Handle incorrect password or decryption failure
        return None

class Client:
    def __init__(self, host, port):
        """
        Initializes the client.

        :param host: The host IP address.
        :type host: str
        :param port: The port number.
        :type port: int
        """
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_private_key, self.client_public_key = None, None
        self.server_public_key = None
        self.mac_key = None
        self.username = None
        self.action = None
        self.download_event = threading.Event()

    def create_new_user(self):
        """
        Creates a new user with a new private key pair.
        """
        self.username = input("Enter your Name: ")
        passphrase = input("Enter a password for the new user: ")
        self.client_private_key, self.client_public_key = generate_key_pair()

        # Encrypt and save the private key to a file
        encrypted_private_key = encrypt_private_key(self.client_private_key, passphrase)
        with open(f"client_key/{self.username}.pem", "wb") as key_file:
            key_file.write(encrypted_private_key)
        print(f"Private key for user {self.username} saved to {self.username}.pem")

    def load_existing_user(self):
        """
        Loads an existing user's private key from a file.
        If the file doesn't exist or the passphrase is incorrect, prompts to create a new user.
        """
        self.username = input("Enter your Name: ")
        passphrase = input("Enter the password for the existing user: ")
        try:
            with open(f"client_key/{self.username}.pem", "rb") as key_file:
                encrypted_private_key = key_file.read()
                self.client_private_key = decrypt_private_key(encrypted_private_key, passphrase)
                self.client_public_key = self.client_private_key.public_key()
                if self.client_private_key is None:
                    raise ValueError("Incorrect password or decryption failure")
            print(f"Private key for user {self.username} loaded successfully.")
        except FileNotFoundError:
            print(f"User {self.username} not found. Please choose a new user.")
            self.create_new_user()

    def send_message(self):
        """
        Sends messages from the client to the server.
        """
        try:
            while True:
                message = input("Message: ")
                if message == '/download':
                    print("Downloading messages...\n")
                    self.action = '/download'
                if message == '/read':
                    print("Fetching messages...\n")
                    self.action = '/read'
                elif message == '/exit':
                    self.client_socket.close()
                encrypted_message = encrypt_rsa(message.encode('utf-8'), self.server_public_key)
                digest_to_send = generate_digest(encrypted_message, self.mac_key, 'sha256')
                data_to_send = encrypted_message + 'ç'.encode('utf-8') + digest_to_send
                self.client_socket.send(data_to_send)
        except Exception as e:
            print(f"Error sending message: {e}")

    def receive_public_key_and_mac_key(self):
        """
        Receives the server's public key and the encrypted MAC key from the server.
        """
        try:
            public_key_bytes = self.client_socket.recv(2048)
            self.server_public_key = RSA.import_key(public_key_bytes.decode('utf-8'))
            print("Received server's public key.")
            self.client_socket.send(self.client_public_key.export_key())
            print("Sent client's public key to the server.")
            encrypted_mac_key = self.client_socket.recv(2048)
            self.mac_key = decrypt_rsa(encrypted_mac_key, self.client_private_key)
            print(f"Received and decrypted MAC key from the server: {self.mac_key.hex()}")

        except Exception as e:
            print(f"Error during key exchange: {e}")

    def remove_last_line(self):
        """
        Removes the last line printed on the console.
        """
        sys.stdout.write('\033[F')
        sys.stdout.write('\033[K')

    def receive_messages(self):
        """
        Receives and displays messages from the server.
        """
        try:
            received_file = ""
            while True:
                data = self.client_socket.recv(2048)
                if not data:
                    break
                message_received, received_digest = data.split('ç'.encode('utf-8'))
                generated_digest = generate_digest(message_received, self.mac_key, 'sha256')
                is_integrity_verified = verify_digest(received_digest, generated_digest)
                if is_integrity_verified:
                    if len(message_received) < 150:
                        decrypted_message = decrypt_rsa(message_received, self.client_private_key)
                    else:
                        decrypted_message = decrypt_rsa_in_chunks(message_received, self.client_private_key)
                    message_to_display = decrypted_message.decode('utf-8')
                    if self.action == "/download":            
                        if message_to_display != "------ END OF FILE ------":
                            received_file += message_to_display
                        else:
                            self.download_messages(received_file,self.username)
                            print("------ END OF FILE ------\n")
                            self.action = None
                    elif self.action == "/read":            
                        if message_to_display != "------ END OF FILE ------":
                            print(f"{message_to_display}")
                        else:
                            print("------ END OF FILE ------\n")
                            self.action = None
                    else:
                        print(f"\r{message_to_display}\t\t\n", end=' ',flush=True)
        except Exception as e:
            print(f"Error receiving message: {e}")

    def download_messages(self,messages_to_display, username):
        """
        Downloads and saves messages received from the server to a file.

        :param messages_to_display: The messages to be downloaded.
        :type messages_to_display: str
        :param username: The username of the client.
        :type username: str
        """
        base_filename = f"{username}_downloaded_messages.txt"
        counter = 0
        while True:
            filename = base_filename if counter == 0 else f"{base_filename[:-4]}({counter}).txt" 
            if not os.path.exists(filename):
                break
            counter += 1
        with open(filename, 'w') as file:
            for message in messages_to_display:
                file.write(message)
        self.download_event.set()

    def start(self):
        """
        Starts the client.
        """
        try:
            print("****************************************")
            print("***        Encrypted chat            ***")
            print("** /read - read all messages sent    ***")
            print("** /download - Download all messages ***")
            print("** /exit - leave                     ***")
            print("****************************************")
            self.client_socket.connect((self.host, self.port))
            print(f"Connected to the server at {self.host}:{self.port}")

            existing_user = input("Do you want to use an existing user? (yes/no): ").lower()
            if existing_user == 'yes':
                self.load_existing_user()
            elif existing_user == 'no':
                self.create_new_user()
            else:
                print("Invalid option! Leaving...")
                return
            self.client_socket.send(self.username.encode('utf-8'))
            self.receive_public_key_and_mac_key()

            send_thread = threading.Thread(target=self.send_message)
            receive_thread = threading.Thread(target=self.receive_messages)

            send_thread.start()
            receive_thread.start()

            send_thread.join()
            receive_thread.join()
        except KeyboardInterrupt:
            print("Client terminated.")
        finally:
            self.client_socket.close()

# Initialize and start the client
client = Client('127.0.0.1', 5555)
client.start()
