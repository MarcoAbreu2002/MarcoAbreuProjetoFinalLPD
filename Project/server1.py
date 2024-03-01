import time
import base64
import binascii
import getpass
from hashlib import scrypt, sha256
import os
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
import socket
from Crypto.Cipher import AES, PKCS1_OAEP
import threading
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
from encryption import generate_key_pair, encrypt_rsa, decrypt_rsa
from integrity import generate_digest, verify_digest

def encrypt_private_key(private_key, passphrase):
    """
    Encrypts a private key with a passphrase.

    :param private_key: The private key to be encrypted.
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
    :param passphrase: The passphrase used for decryption.
    :type passphrase: str
    :return: The decrypted private key.
    :rtype: RSA.RsaKey or None
    """
    try:
        private_key = RSA.import_key(encrypted_key_data, passphrase=passphrase)
        return private_key
    except ValueError:
        # Handle incorrect password or decryption failure
        return None

class Server:
    def __init__(self, host, port):
        """
        Initializes the Server object.

        :param host: The host IP address.
        :type host: str
        :param port: The port number.
        :type port: int
        """
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.users = {}
        self.private_key = None
        self.public_key = None
        if os.path.exists("server_private_key_encrypted.pem"):
            with open("server_private_key_encrypted.pem", "rb") as f:
                encrypted_private_key = f.read()
            password = input("Enter the password to decrypt the private key: ")
            self.private_key = decrypt_private_key(encrypted_private_key, password)
            self.public_key = self.private_key.public_key()
            if self.private_key is None:
                print("Incorrect password or private key decryption failure. Exiting.")
                return
        else:
            self.private_key, self.public_key = generate_key_pair()
            password = input("Enter a password to encrypt the private key: ")
            encrypted_private_key = encrypt_private_key(self.private_key, password)
            with open("server_private_key_encrypted.pem", "wb") as f:
                f.write(encrypted_private_key)

        self.mac_key = None
        self.digest = None

    def generate_user_mac_key(self):
        """
        Generates a random MAC key for a user.

        :return: The generated MAC key.
        :rtype: bytes
        """
        return get_random_bytes(32)  # 32 bytes for a 256-bit key

    def setup_database(self):
        """
        Sets up the SQLite database for storing messages.
        """
        cursor = None
        try:
            with sqlite3.connect('MESI_LPD.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        data BLOB 
                    )
                ''')
                conn.commit()
        except Exception as e:
            print(f"Error setting up the database: {e}")
        finally:
            if cursor:
                cursor.close()

    def register_user(self, username, client_socket, client_public_key):
        """
        Registers a user with their username, socket, and public key.

        :param username: The username of the user.
        :type username: str
        :param client_socket: The socket object associated with the user.
        :type client_socket: socket.socket
        :param client_public_key: The public key of the user.
        :type client_public_key: RSA.RsaKey
        """
        mac_key = self.generate_user_mac_key()
        self.users[username] = {
            'socket': client_socket,
            'public_key': client_public_key,
            'mac_key': mac_key,
        }
        print(f"Generated MAC key for {username}: {mac_key.hex()}")

    # Storing using asymmetric key
    def store_message(self, sender, message):
        """
        Stores a message from a sender.

        :param sender: The username of the sender.
        :type sender: str
        :param message: The message to store.
        :type message: str
        """
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            built_message = f"{timestamp} {sender} : {message}\n"
            encrypted_message = encrypt_rsa(built_message.encode('utf-8'), self.users[sender]['public_key'])
            with open(f"client_messages/{sender}_log_messages_encrypted.txt", 'ab') as file:
                file.write(encrypted_message)
        except Exception as e:
            print(f"Error storing message in the file: {e}")

    def encrypt_file(self, plaintext, public_key, username):
        """
        Encrypts a plaintext file.

        :param plaintext: The plaintext to encrypt.
        :type plaintext: str
        :param public_key: The public key for encryption.
        :type public_key: RSA.RsaKey
        :param username: The username associated with the plaintext.
        :type username: str
        """
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            built_message = f"{timestamp} {username}: {plaintext} \n"
            ciphertext = encrypt_rsa(built_message.encode('utf-8'), public_key)
            conn = sqlite3.connect('MESI_LPD.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO messages (data)
                VALUES (?)
            ''', (ciphertext,))
            conn.commit()
        except Exception as e:
            print(f"Failed to write in the database: {e}")
        finally:
            cursor.close()
            conn.close()

    def send_mac_key_encrypted(self, client_socket, client_public_key):
        """
        Sends the MAC key encrypted to a client.

        :param client_socket: The client socket.
        :type client_socket: socket.socket
        :param client_public_key: The client's public key.
        :type client_public_key: RSA.RsaKey
        """
        try:
            for username, user_data in self.users.items():
                if user_data['socket'] == client_socket:
                    mac_key_to_encrypt = user_data['mac_key']
                    encrypted_mac_key = encrypt_rsa(mac_key_to_encrypt, client_public_key)
                    client_socket.send(encrypted_mac_key)
                    break
        except Exception as e:
            print(f"Failed to send encrypted MAC key: {e}")

    def send_public_key(self, client_socket):
        """
        Sends the server's public key to a client.

        :param client_socket: The client socket.
        :type client_socket: socket.socket
        """
        public_key_bytes = self.public_key.export_key()
        client_socket.sendall(public_key_bytes)

    def handle_client(self, client_socket, client_address):
        """
        Handles communication with a client.

        :param client_socket: The client socket.
        :type client_socket: socket.socket
        :param client_address: The client's address.
        :type client_address: tuple
        """
        username = None
        self.setup_database()
        try:
            data = client_socket.recv(2048)
            username = data.decode('utf-8')
            self.register_user(username, client_socket, None)

            self.send_public_key(client_socket)

            client_public_key_bytes = client_socket.recv(2048)
            client_public_key = RSA.import_key(client_public_key_bytes.decode('utf-8'))
            self.users[username]['public_key'] = client_public_key
            print(f"Received public key from {username}.")

            self.send_mac_key_encrypted(client_socket, client_public_key)

            while True:
                data = client_socket.recv(2048)
                if not data:
                    break
                received_data = data.split('ç'.encode('utf-8'))
                encrypted_message, received_digest = received_data[0], received_data[1]
                stored_digest = generate_digest(encrypted_message, self.users[username]['mac_key'], 'sha256')
                is_integrity_verified = verify_digest(received_digest, stored_digest)
                if is_integrity_verified:
                    sender_public_key = self.users[username]['public_key']
                    decrypted_message = decrypt_rsa(encrypted_message, self.private_key)
                    message = decrypted_message.decode('utf-8')
                    print(f"Received from {username}: {message}")
                    self.encrypt_file(message, self.public_key, username)
                    if message == "/read" or message == "/download":
                        self.send_log_messages(client_socket, username)
                        self.store_message(username, message)
                    elif message == "/remove":
                        self.remove_log_messages(client_socket, username)
                        self.store_message(username, message)
                    else:
                        self.broadcast(message, username)
                        self.store_message(username, message)
                else:
                    print(f"Integrity verification failed for the received message.")
        except Exception as e:
            print(f"Error in communication with {client_address}: {e}")
        finally:
            client_socket.close()
            if username in self.users:
                del self.users[username]
                print(f"Connection closed with {client_address}")
            else:
                print(f"Connection closed with {client_address}, user {username} not found in the registry.")

    def broadcast(self, message, sender_username):
        """
        Broadcasts a message to all users except the sender.

        :param message: The message to broadcast.
        :type message: str
        :param sender_username: The username of the sender.
        :type sender_username: str
        """
        for username, user_data in self.users.items():
            if username != sender_username:
                try:
                    client_public_key = self.users[username]['public_key']
                    message_to_send = f"{sender_username} : {message}"
                    encrypted_message = encrypt_rsa(message_to_send.encode('utf-8'), client_public_key)
                    hash_to_send = generate_digest(encrypted_message, self.users[username]['mac_key'], 'sha256')
                    data_to_send = encrypted_message + 'ç'.encode('utf-8') + hash_to_send
                    user_data['socket'].send(data_to_send)
                except Exception as e:
                    print(f"Failed to send message to {username}: {e}")

    def send_message(self, client_socket, message, sender_username):
        """
        Sends a message to a client.

        :param client_socket: The client socket.
        :type client_socket: socket.socket
        :param message: The message to send.
        :type message: str
        :param sender_username: The username of the sender.
        :type sender_username: str
        """
        try:
            encrypted_message = encrypt_rsa(message.encode('utf-8'), self.users[sender_username]['public_key'])
            hash_to_send = generate_digest(encrypted_message, self.users[sender_username]['mac_key'], 'sha256')
            data_to_send = encrypted_message + 'ç'.encode('utf-8') + hash_to_send
            client_socket.send(data_to_send)
        except Exception as e:
            print(f"Failed to send message to {sender_username}: {e}")

    def remove_log_messages(self, client_socket, sender_username):
        """
        Removes log messages for a user.

        :param client_socket: The client socket.
        :type client_socket: socket.socket
        :param sender_username: The username of the sender.
        :type sender_username: str
        """
        try:
            file_name = f"client_messages/{sender_username}_log_messages_encrypted.txt"
            file_path = os.path.join(os.path.dirname(__file__), file_name)
            if os.path.exists(file_path):
                os.remove(file_path)
                success_message = f"Log messages file for {sender_username} removed successfully."
                self.send_message(client_socket, success_message, sender_username)
                print(success_message)
            else:
                not_found_message = f"Log messages file for {sender_username} not found."
                self.send_message(client_socket, not_found_message, sender_username)
                print(not_found_message)
        except Exception as e:
            error_message = f"Failed to remove log messages for {sender_username}: {e}"
            self.send_message(client_socket, error_message, sender_username)

    def send_log_messages(self, client_socket, sender_username):
        """
        Sends log messages to a client.

        :param client_socket: The client socket.
        :type client_socket: socket.socket
        :param sender_username: The username of the sender.
        :type sender_username: str
        """
        try:
            file_name = f"client_messages/{sender_username}_log_messages_encrypted.txt"
            file_path = os.path.join(os.path.dirname(__file__), file_name)
            if os.path.exists(file_path):
                with open(file_path, 'rb') as file:
                    file_data = file.read()
                chunk_size = 256
                for i in range(0, len(file_data), chunk_size):
                    chunk = file_data[i:i + chunk_size]
                    hash_to_send = generate_digest(chunk, self.users[sender_username]['mac_key'], 'sha256')
                    chunk_to_send = chunk + 'ç'.encode('utf-8') + hash_to_send
                    client_socket.send(chunk_to_send)
                    time.sleep(0.01)
                self.send_message(client_socket, "------ END OF FILE ------", sender_username)
                print(f"Log messages sent to {sender_username} successfully.")
            else:
                self.send_message(client_socket, f"Log messages file for {sender_username} not found.", sender_username)
        except Exception as e:
            self.send_message(client_socket, f"Failed to send log messages to {sender_username}: {e}", sender_username)

    def start(self):
        """
        Starts the server and listens for incoming connections.
        """
        print(f"Listening to {self.host}:{self.port}")
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_handler.start()
        except KeyboardInterrupt:
            print("Server shutdown.")

# Initialize and start the server
server = Server('127.0.0.1', 5555)
server.start()
