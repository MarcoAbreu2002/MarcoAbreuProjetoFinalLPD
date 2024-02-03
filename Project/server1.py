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
        if os.path.exists("server_private_key_encrypted.pem"):
            with open("server_private_key_encrypted.pem", "rb") as f:
                encrypted_private_key = f.read()
            password = input("Digite a senha para desencriptar a chave privada: ")
            self.private_key = decrypt_private_key(encrypted_private_key, password)
            self.public_key = self.private_key.public_key()
	   # print(self.private_key.export_key())
           # print(self.private_key.publickey().export_key().decode('utf-8'))
            if self.private_key is None:
                print("Senha incorreta ou falha na desencriptação da chave privada. Saindo.")
                return
        else:
            self.private_key, self.public_key = generate_key_pair()
            password = input("Digite uma senha para encriptar a chave privada: ")
            encrypted_private_key = encrypt_private_key(self.private_key, password)
            #save the encrypted private key to a file
            with open("server_private_key_encrypted.pem", "wb") as f:
                f.write(encrypted_private_key)

        self.mac_key = None
        self.digest = None

    def generate_user_mac_key(self):
        return get_random_bytes(32)  # 32 bytes for a 256-bit key

    def setup_database(self):
        cursor = None  # Initialize cursor outside the try block
        try:
            # Create a new SQLite connection and cursor
            with sqlite3.connect('MESI_LPD.db') as conn:
                cursor = conn.cursor()

                # Execute SQL command to create a 'messages' table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        data BLOB 
                    )
                ''') 

                # Commit the changes
                conn.commit()

        except Exception as e:
            print(f"Error setting up the database: {e}")
        finally:
            # Close the cursor and connection (if they are not None)
            if cursor:
                cursor.close()


    def register_user(self, username, client_socket, client_public_key):
        mac_key = self.generate_user_mac_key()
        self.users[username] = {
            'socket': client_socket,
            'public_key': client_public_key,
            'mac_key': mac_key,
        }
        print(f"Generated MAC key for {username}: {mac_key.hex()}")



#Storing using asymmetric key
    def store_message(self, sender, message):
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            built_message = f"{timestamp} {sender} : {message}\n"
            encrypted_message = encrypt_rsa(built_message.encode('utf-8'), self.users[sender]['public_key']) 
            with open(f"client_messages/{sender}_log_messages_encrypted.txt", 'ab') as file:
                file.write(encrypted_message)
        except Exception as e:
            print(f"Error storing message in the file: {e}")
        finally:
            # Close the file
            file.close()


    def encrypt_file(self, plaintext, public_key, username):
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            built_message = f"{timestamp} {username}: {plaintext} \n"
            ciphertext = encrypt_rsa(built_message.encode('utf-8'), public_key)

            # Connect to the SQLite database
            conn = sqlite3.connect('MESI_LPD.db')
            cursor = conn.cursor()

            # Insert the ciphertext into the 'messages' table
            cursor.execute('''
                INSERT INTO messages (data)
                VALUES (?)
            ''', (ciphertext,))

            # Commit the changes
            conn.commit()

        except Exception as e:
            print(f"Failed to write in the database: {e}")
        finally:
            # Close the cursor and connection
            cursor.close()
            conn.close()


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
        client_socket.sendall(public_key_bytes)

    def handle_client(self, client_socket, client_address):
        username = None
        self.setup_database()
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

                received_data = data.split('ç'.encode('utf-8'))
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
                    self.encrypt_file(message,self.public_key,username)
                    if message == "/read" or message == "/download":
                        self.send_log_messages(client_socket, username)
                        self.store_message(username,message)
                    elif message == "/remove":
                        self.remove_log_messages(client_socket, username)
                        self.store_message(username,message)
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
        for username, user_data in self.users.items():
            if username != sender_username:
                try:
                    client_public_key = self.users[username]['public_key']
                    message_to_send = f"{sender_username} : {message}"
                    encrypted_message = encrypt_rsa(message_to_send.encode('utf-8'), client_public_key)
                    print("Encrypted message RSA: " + encrypted_message.hex())

                    hash_to_send = generate_digest(encrypted_message, self.users[username]['mac_key'], 'sha256')

                    print("Encrypted message: " + encrypted_message.hex())
                    data_to_send = encrypted_message + 'ç'.encode('utf-8') + hash_to_send
                    user_data['socket'].send(data_to_send)
                except Exception as e:
                    print(f"Failed to send message to {username}: {e}")

    def send_message(self, client_socket, message, sender_username):
        try:
            encrypted_message = encrypt_rsa(message.encode('utf-8'), self.users[sender_username]['public_key'])
            hash_to_send = generate_digest(encrypted_message, self.users[sender_username]['mac_key'], 'sha256')
            data_to_send = encrypted_message + 'ç'.encode('utf-8') + hash_to_send
            client_socket.send(data_to_send)
        except Exception as e:
            print(f"Failed to send message to {sender_username}: {e}")

    def remove_log_messages(self, client_socket, sender_username):
        try:
            # Construct the file path based on the sender's username
            file_name = f"client_messages/{sender_username}_log_messages_encrypted.txt"
            file_path = os.path.join(os.path.dirname(__file__), file_name)
            # Check if the file exists before attempting to remove it
            if os.path.exists(file_path):
                os.remove(file_path)
                # Invoke the send_message function with a success message
                success_message = f"Log messages file for {sender_username} removed successfully."
                self.send_message(client_socket, success_message,sender_username)
                # Print the success message to the console
                print(success_message)
            else:
                # If the file is not found, send an appropriate message
                not_found_message = f"Log messages file for {sender_username} not found."
                self.send_message(client_socket, not_found_message,sender_username)
                # Print the not found message to the console
                print(not_found_message)
        except Exception as e:
            # If an error occurs, send an error message
            error_message = f"Failed to remove log messages for {sender_username}: {e}"
            self.send_message(client_socket, error_message,sender_username)

    def send_log_messages(self, client_socket, sender_username):
        try:
            # Construct the file path based on the sender's username
            file_name = f"client_messages/{sender_username}_log_messages_encrypted.txt"
            file_path = os.path.join(os.path.dirname(__file__), file_name)

            # Check if the file exists before attempting to send it
            if os.path.exists(file_path):
                with open(file_path, 'rb') as file:
                    file_data = file.read()

                # Send file data in 2048-byte chunks
                chunk_size = 256
                for i in range(0, len(file_data), chunk_size):
                    chunk = file_data[i:i + chunk_size]
                    hash_to_send = generate_digest(chunk, self.users[sender_username]['mac_key'], 'sha256')
                    chunk_to_send = chunk + 'ç'.encode('utf-8') + hash_to_send
                    client_socket.send(chunk_to_send)
                    time.sleep(0.01)
                self.send_message(client_socket, "------ END OF FILE ------",sender_username)
                print(f"Log messages sent to {sender_username} successfully.")
            else:
                self.send_message(client_socket, f"Log messages file for {sender_username} not found.", sender_username)
        except Exception as e:
            self.send_message(client_socket, f"Failed to send log messages to {sender_username}: {e}", sender_username)



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

server = Server('127.0.0.1', 5555)
server.start()
