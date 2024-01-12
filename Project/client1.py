import socket
import threading
from Crypto.PublicKey import RSA
from encryption import generate_key_pair, encrypt_rsa, decrypt_rsa

class Client:
    def __init__(self, host, port, username):
        self.host = host
        self.port = port
        self.username = username
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_public_key = None

    def send_message(self):
        try:
            while True:
                message = input("Digite sua mensagem: ")
                encrypted_message = encrypt_rsa(message.encode('utf-8'), self.server_public_key)
                self.client_socket.send(encrypted_message)
        except Exception as e:
            print(f"Erro ao enviar mensagem: {e}")

    def receive_public_key(self):
        try:
            public_key_bytes = self.client_socket.recv(2048)
            self.server_public_key = RSA.import_key(public_key_bytes)
            print("Received server's public key.")
        except Exception as e:
            print(f"Error receiving server's public key: {e}")

    def receive_messages(self):
        try:
            while True:
                data = self.client_socket.recv(2048)
                if not data:
                    break
                # Decrypt the received message using the server's public key
                decrypted_message = decrypt_rsa(data, generate_key_pair()[0])
                print("Key: " + self.generate_key_pair()[0].export_key().decode('utf-8'))
                message = decrypted_message.decode('utf-8')
                print(message)
        except Exception as e:
            print(f"Erro ao receber mensagem: {e}")

    def start(self):
        try:
            self.client_socket.connect((self.host, self.port))
            print(f"Conectado ao servidor em {self.host}:{self.port}")
            self.client_socket.send(self.username.encode('utf-8'))

            # Receive the server's public key
            self.receive_public_key()

            send_thread = threading.Thread(target=self.send_message)
            receive_thread = threading.Thread(target=self.receive_messages)

            send_thread.start()
            receive_thread.start()

            send_thread.join()
            receive_thread.join()
        except KeyboardInterrupt:
            print("Cliente encerrado.")
        finally:
            self.client_socket.close()

# Exemplo de utilização
username = input("Enter your Name: ")
client = Client('127.0.0.1', 5556, username)
client.start()
