import os
import socket
import threading
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
from encryption import generate_key_pair, encrypt_rsa, decrypt_rsa
from integrity import generate_digest, verify_digest


# Função para encriptar a chave privada
def encrypt_private_key(private_key, password):
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key.export_key())
    return key + cipher.nonce + tag + ciphertext

def decrypt_private_key(encrypted_private_key, password):
    key = encrypted_private_key[:32]
    nonce = encrypted_private_key[32:44]
    tag = encrypted_private_key[44:60]
    ciphertext = encrypted_private_key[60:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        private_key = RSA.import_key(cipher.decrypt_and_verify(ciphertext, tag))
        return private_key
    except ValueError as e:
        print(f"Falha na desencriptação da chave privada: {e}")
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

        # Verifica se a chave privada já está armazenada
        if os.path.exists("server_private_key_encrypted.bin"):
            with open("server_private_key_encrypted.bin", "rb") as f:
                encrypted_private_key = f.read()
            password = input("Digite a senha para desencriptar a chave privada: ")
            self.private_key = decrypt_private_key(encrypted_private_key, password)
            if self.private_key is None:
                # Senha incorreta ou falha na desencriptação
                print("Senha incorreta ou falha na desencriptação da chave privada. Saindo.")
                return
        else:
            # Se não existe, gera uma nova chave privada
            self.private_key, self.public_key = generate_key_pair()
            # Encripta e salva a chave privada
            password = input("Digite uma senha para encriptar a chave privada: ")
            encrypted_private_key = encrypt_private_key(
                self.private_key,
                password
            )
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

    def store_message(self, sender, message, sender_public_key):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        filename = f"{sender}_messages.pem"
        formatted_message = f'[{timestamp}] {sender}: {message}\n'
        encrypted_formatted_message = encrypt_rsa(formatted_message.encode('utf-8'), sender_public_key)

        with open(filename, 'a', encoding='utf-8') as file:
            file.write(encrypted_formatted_message.decode('utf-8', errors='ignore'))

    def encrypt_file(self, plaintext, public_key):
        ciphertext = encrypt_rsa(plaintext, public_key)
        with open('log_messages_encrypted.pem', 'wb') as file:
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
        client_socket.sendall(public_key_bytes)

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
                        self.store_message(username, decrypted_message, sender_public_key)
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
            filename = f"{sender_username}_messages.pem"
            with open(filename, 'rb') as file:
                encrypted_contents = file.read()

            hash_to_send = generate_digest(encrypted_contents, self.users[sender_username]['mac_key'], 'sha256')
            data_to_send = encrypted_contents + b' : ' + hash_to_send
            client_socket.sendall(data_to_send)
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

server = Server('127.0.0.1', 5555)
server.start()
