import os
import shutil
from datetime import datetime
import socket
import threading
import cryptography
import base64

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.users = {}
    
    def register_user(self,username, client_socket):
        private_key = rsa.generate_private_key(
            p_exp = 65537,
            key_size = 2048,
            backend = default_backend()
        )
        public_key = private_key.public_key()
        print("Pkey: " + private_key)
        print("usrena: " + username)

        self.users[username] = {
            'private_key' : private_key,
            'public_key' : public_key,
            'socket' : client_socket
        }


    def store_message(self, sender, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
        with open(f'log_messages.txt', 'a') as file:
            if isinstance(message, bytes):
                # Decode bytes to string using the appropriate encoding (e.g., UTF-8)
                message = message.decode('utf-8')
            formatted_message = f'[{timestamp}] {sender}: {message}\n'
            file.write(formatted_message)


    def encrypt_file(self, public_key):
        with open('log_messages.txt', 'rb') as file:
            plaintext = file.read()
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open('log_messages_encrypted.txt', 'wb') as file:
            file.write(ciphertext)

    def send_log_messages(self, client_socket, sender_username, private_key):
        try:
            self.encrypt_file(private_key.public_key())

            with open('log_messages_encrypted.txt', 'rb') as file:
                encrypted_contents = file.read()

            client_socket.send(encrypted_contents)
        except Exception as e:
            print(f"Failed to send log messages to {sender_username}: {e}")
        finally:
            # Clean up the temporary encrypted file
            os.remove('log_messages_encrypted.txt')

    def handle_client(self, client_socket, client_address):
        try:
            data = client_socket.recv(1024)
            username = data.decode('utf-8')
            self.register_user(username, client_socket)

            while True:
                data = client_socket.recv(1024)
                message = data.decode('utf-8')
                print(f"Recebido de {username}: {message}")

                if message == "/read":
                    self.send_log_messages(client_socket, username)
                else:
                    self.broadcast(message, username)
                    self.store_message(username, data)

        except Exception as e:
            print(f"Erro na comunicação com {client_address}: {e}")
        finally:
            client_socket.close()
            if username in self.users:
                del self.users[username]
                print(f"Conexão encerrada com {client_address}")
            else:
                print(f"Conexão encerrada com {client_address}, usuário {username} não encontrado no registro.")

    def broadcast(self, message, sender_username):
        for username, user_data in self.users.items():
            if username != sender_username:
                try:
                    user_data['socket'].send((sender_username + " : " + message).encode('utf-8'))
                except Exception as e:
                    print(f"Failed to send message to {username}: {e}")  

    def start(self):
        print(f"Listenning to {self.host}:{self.port}")
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
        