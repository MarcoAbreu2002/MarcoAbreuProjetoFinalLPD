import os
import socket
import threading
from encryption import generate_key_pair, encrypt_rsa, decrypt_rsa
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from integrity import generate_digest, verify_digest
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
        self.mac_key = None
        self.digest = None

    def generate_user_mac_key(self):
        # Generate a unique MAC key for each user
        return get_random_bytes(32)  # 32 bytes for a 256-bit key

    def register_user(self, username, client_socket, client_public_key):
        # Generate and store a unique MAC key for each user
        mac_key = self.generate_user_mac_key()
        self.users[username] = {
            'socket': client_socket,
            'public_key': client_public_key,
            'mac_key': mac_key
        }
        print(f"Generated MAC key for {username}: {mac_key.hex()}")


    def store_message(self, sender, message, sender_public_key):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(f"{sender}_messages.txt", 'a', encoding='utf-8') as file:
            if isinstance(message, bytes):
                try:
                    # Decode bytes to string using the appropriate encoding (e.g., UTF-8)
                    message = message.decode('utf-8', errors='ignore')
                except UnicodeDecodeError as e:
                    print(f"Error decoding message: {e}")
                    # Handle the error as needed

            formatted_message = f'[{timestamp}] {sender}: {message}\n'
            encrypted_formatted_message = encrypt_rsa(formatted_message.encode('utf-8'), sender_public_key)
            file.write(encrypted_formatted_message.decode('utf-8', errors='ignore'))



    def encrypt_file(self, plaintext, public_key):
        ciphertext = encrypt_rsa(plaintext, public_key)
        with open('log_messages_encrypted.txt', 'wb') as file:
            file.write(ciphertext)

    def send_log_messages(self, client_socket, sender_username):
        try:
            with open(f"{sender_username}_messages.txt", 'rb') as file:
                encrypted_contents = file.read()
            hash_to_send = generate_digest(encrypted_contents, self.users[sender_username]['mac_key'], 'sha256')
            data_to_send = encrypted_contents + b' : ' + hash_to_send 
            client_socket.send(data_to_send)
        except Exception as e:
            print(f"Failed to send log messages to {sender_username}: {e}")
        

    def send_mac_key_encrypted(self, client_socket, client_public_key):
        try:
            for username, user_data in self.users.items():
                if user_data['socket'] == client_socket:
                    mac_key_to_encrypt = user_data['mac_key']
                    # Encrypt the MAC key with the client's public key
                    encrypted_mac_key = encrypt_rsa(mac_key_to_encrypt, client_public_key)
                    client_socket.send(encrypted_mac_key)
                    break  # Termina o loop após encontrar o usuário correspondente
        except Exception as e:
            print(f"Failed to send encrypted MAC key: {e}")


    def send_public_key(self, client_socket):
        public_key_bytes = self.public_key.export_key()
        client_socket.sendall(public_key_bytes)


    def handle_client(self, client_socket, client_address):
        try:
            data = client_socket.recv(2048)
            username = data.decode('utf-8')
            # Generate and store a unique MAC key for the user
            self.register_user(username, client_socket, None)  # Placeholder for public key

            # Send the server's public key to the client
            self.send_public_key(client_socket)

            # Receive the client's public key
            client_public_key_bytes = client_socket.recv(2048)
            client_public_key = RSA.import_key(client_public_key_bytes.decode('utf-8'))
            self.users[username]['public_key'] = client_public_key
            print(f"Received public key from {username}.")

            # Send the encrypted MAC key to the client
            self.send_mac_key_encrypted(client_socket, client_public_key)

            while True:
                data = client_socket.recv(2048)
                if not data:
                    break

                received_data = data.split(b' : ')
                encrypted_message, received_digest = received_data[0], received_data[1]
                print("Encrypted messaeg: " + data.hex())


                print("Checking digest...")
                print("Check key: " + self.users[username]['mac_key'].hex())

                stored_digest = generate_digest(encrypted_message, self.users[username]['mac_key'], 'sha256')
                print("received digest: " + received_digest.hex())
                print("generated digest: " + stored_digest.hex())
                # Verify the integrity of the received message
                is_integrity_verified = verify_digest(received_digest, stored_digest)

                if is_integrity_verified:
                    # Continue processing the message if integrity is verified
                    sender_public_key = self.users[username]['public_key']
                    decrypted_message = decrypt_rsa(encrypted_message, self.private_key)
                    message = decrypted_message.decode('utf-8')

                    print(f"Received from {username}: {message}")
                    if message == "/read":
                        self.send_log_messages(client_socket, username)
                    else:
                        self.broadcast(message, username)
                        self.store_message(username, decrypted_message,sender_public_key)
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
                    # Combine username and message
                    message_to_send = f"{sender_username} : {message}"
                    print("Broadcasting...")

                    # Encrypt the message with the public key of each user before sending
                    encrypted_message = encrypt_rsa(message_to_send.encode('utf-8'), client_public_key)
                    print("Encrypted message RSA: " + encrypted_message.hex())
                    if encrypted_message is None:
                        print(f"Encryption failed for user {username}. Skipping.")
                        continue

                    # Generate hash for data integrity
                    hash_to_send = generate_digest(encrypted_message, self.users[username]['mac_key'], 'sha256')

                    # Attach both the encrypted message and the digest when sending
                    print("Encrypted message: " + encrypted_message.hex())
                    data_to_send = encrypted_message + b' : ' + hash_to_send 
                    user_data['socket'].send(data_to_send)
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
