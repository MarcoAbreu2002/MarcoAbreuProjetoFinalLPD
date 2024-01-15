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

# Create a SQLite database connection
conn = sqlite3.connect('MESI_LPD.db')

# Create a cursor object
cursor = conn.cursor()

# Execute SQL command to create a 'messages' table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        message TEXT,
        timestamp DATETIME
    )
''')

# Commit the changes
conn.commit()

def encrypt_private_key(private_key, passphrase):
    # Encrypt the private key with the passphrase
    encrypted_key = private_key.export_key(passphrase=passphrase, pkcs=8, protection="scryptAndAES128-CBC")
    return encrypted_key

def decrypt_private_key(encrypted_key_data, passphrase):
    # Decrypt the private key
    try:
        private_key = RSA.import_key(encrypted_key_data, passphrase=passphrase)
        return private_key
    except ValueError:
        # Handle incorrect password or decryption failure
        return None

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.users = {}
        self.private_key = None
        self.public_key = None

        # Your existing code with modifications
        if os.path.exists("server_private_key_encrypted.bin"):
            with open("server_private_key_encrypted.bin", "rb") as f:
                encrypted_private_key = f.read()
            password = input("Digite a senha para desencriptar a chave privada: ")
            self.private_key = decrypt_private_key(encrypted_private_key, password)
            print(self.private_key.export_key())
            print(self.private_key.publickey().export_key().decode('utf-8'))
            if self.private_key is None:
                print("Senha incorreta ou falha na desencriptação da chave privada. Saindo.")
                return
        else:
            self.private_key, self.public_key = generate_key_pair()
            print(self.private_key.export_key())
            print(self.public_key.export_key())
            password = input("Digite uma senha para encriptar a chave privada: ")
            encrypted_private_key = encrypt_private_key(self.private_key, password)
            # Save the encrypted private key to a file
            with open("server_private_key_encrypted.bin", "wb") as f:
                f.write(encrypted_private_key)

        self.mac_key = None
        self.digest = None

    def generate_user_mac_key(self):
        return get_random_bytes(32)  # 32 bytes for a 256-bit key

    def register_user(self, username, client_socket, client_public_key):
        mac_key = self.generate_user_mac_key()
        self.users[username] = {
            'socket': client_socket,
            'public_key': client_public_key,
            'mac_key': mac_key
        }
        print(f"Generated MAC key for {username}: {mac_key.hex()}")

    def store_message(self, sender, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Insert message into the 'messages' table
        cursor.execute('INSERT INTO messages (sender, message, timestamp) VALUES (?, ?, ?)',
                       (sender, message, timestamp))

        # Commit the changes
        conn.commit()

    def encrypt_file(self, plaintext, public_key):
        ciphertext = encrypt_rsa(plaintext, public_key)
        with open('log_messages_encrypted.txt', 'wb') as file:
            file.write(ciphertext)

    def send_mac_key_encrypted(self, client_socket, client_public_key):
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
        public_key_bytes = self.public_key.export_key()
        client_socket.sendall(self.private_key.publickey().export_key().decode('utf-8'))

    def handle_client(self, client_socket, client_address):
        username = None
        try:
            data = client_socket.recv(2048)
            username = data.decode('utf-8')
            self.register_user(username, client_socket, None)  # Placeholder for public key

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

                received_data = data.split(b' : ')
                encrypted_message, received_digest = received_data[0], received_data[1]
                print("Encrypted message: " + data.hex())

                print("Checking digest...")
                print("Check key: " + self.users[username]['mac_key'].hex())

                stored_digest = generate_digest(encrypted_message, self.users[username]['mac_key'], 'sha256')
                print("received digest: " + received_digest.hex())
                print("generated digest: " + stored_digest.hex())

                is_integrity_verified = verify_digest(received_digest, stored_digest)

                if is_integrity_verified:
                    sender_public_key = self.users[username]['public_key']
                    decrypted_message = decrypt_rsa(encrypted_message, self.private_key)
                    message = decrypted_message.decode('utf-8')

                    print(f"Received from {username}: {message}")
                    if message == "/read":
                        self.send_log_messages(client_socket, username)
                    else:
                        self.broadcast(message, username)
                        self.store_message(username, decrypted_message)
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
        for username, user_data in self.users.items():
            if username != sender_username:
                try:
                    client_public_key = self.users[username]['public_key']
                    message_to_send = f"{sender_username} : {message}"
                    encrypted_message = encrypt_rsa(message_to_send.encode('utf-8'), client_public_key)
                    print("Encrypted message RSA: " + encrypted_message.hex())

                    hash_to_send = generate_digest(encrypted_message, self.users[username]['mac_key'], 'sha256')

                    print("Encrypted message: " + encrypted_message.hex())
                    data_to_send = encrypted_message + b' : ' + hash_to_send
                    user_data['socket'].send(data_to_send)
                except Exception as e:
                    print(f"Failed to send message to {username}: {e}")

    def send_log_messages(self, client_socket, sender_username):
        try:
            # Retrieve messages from the 'messages' table
            cursor.execute('SELECT message, timestamp FROM messages WHERE sender = ?', (sender_username,))
            messages = cursor.fetchall()

            for encrypted_message, timestamp in messages:
                # Decrypt and send messages to the client
                decrypted_message = decrypt_rsa(encrypted_message, self.private_key)
                message = decrypted_message.decode('utf-8')
                data_to_send = f"[{timestamp}] {sender_username}: {message}\n"
                client_socket.sendall(data_to_send.encode('utf-8'))
        except Exception as e:
            print(f"Failed to send log messages to {sender_username}: {e}")

    def start(self):
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

        # Close the database connection
        conn.close()

server = Server('127.0.0.1', 5555)
server.start()
