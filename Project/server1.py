import os
import socket
import threading
from encryption import generate_key_pair, encrypt_rsa, decrypt_rsa
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.users = {}
        self.private_key, self.public_key = generate_key_pair()

    def register_user(self, username, client_socket):
        self.users[username] = {
            'socket': client_socket
        }

    def store_message(self, sender, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(f'log_messages.txt', 'a') as file:
            if isinstance(message, bytes):
                # Decode bytes to string using the appropriate encoding (e.g., UTF-8)
                message = message.decode('utf-8')
            formatted_message = f'[{timestamp}] {sender}: {message}\n'
            file.write(formatted_message)

    def encrypt_file(self, plaintext, public_key):
        ciphertext = encrypt_rsa(plaintext, public_key)
        with open('log_messages_encrypted.txt', 'wb') as file:
            file.write(ciphertext)

    def send_log_messages(self, client_socket, sender_username, public_key):
        try:
            with open('log_messages.txt', 'rb') as file:
                plaintext = file.read()
            self.encrypt_file(plaintext, public_key)

            with open('log_messages_encrypted.txt', 'rb') as file:
                encrypted_contents = file.read()

            client_socket.send(encrypted_contents)
        except Exception as e:
            print(f"Failed to send log messages to {sender_username}: {e}")
        finally:
            # Clean up the temporary encrypted file
            os.remove('log_messages_encrypted.txt')

    
    def send_public_key(self, client_socket):
        public_key_bytes = self.public_key.export_key()
        client_socket.sendall(public_key_bytes)

    def handle_client(self, client_socket, client_address):
        try:
            data = client_socket.recv(2048)
            username = data.decode('utf-8')
            self.register_user(username, client_socket)
            # Send the server's public key to the client
            self.send_public_key(client_socket)
            while True:
                data = client_socket.recv(2048)
                if not data:
                    break
                # Check if the received data represents the server's public key
                if data.startswith(b'-----BEGIN PUBLIC KEY-----'):
                    # Handle the public key separately if needed
                    print("Received server's public key.")
                else:
                    # Decrypt the received message using the server's public key
                    decrypted_message = decrypt_rsa(data, self.private_key)
                    message = decrypted_message.decode('utf-8')
                    print("Key: " + self.private_key.export_key().decode('utf-8'))
                    print(f"Received from {username}: {message}")
                    if message == "/read":
                        self.send_log_messages(client_socket, username, self.public_key)
                    else:
                        self.broadcast(message, username)
                        self.store_message(username, decrypted_message)
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
        # Encrypt the message with the public key of each user before sending
        encrypted_message = encrypt_rsa(message.encode('utf-8'), self.public_key) 
        for username, user_data in self.users.items():
            if username != sender_username:
                try:
                    user_data['socket'].send(encrypted_message)
                except Exception as e:
                    print(f"Failed to send message to {username}: {e}")

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
