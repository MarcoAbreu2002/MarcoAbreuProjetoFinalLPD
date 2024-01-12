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
        self.client_private_key, self.client_public_key = generate_key_pair()  # Generate and store the client's key pair
        self.server_public_key = None

    def send_message(self):
        try:
            while True:
                message = input("Enter your message: ")
                encrypted_message = encrypt_rsa(message.encode('utf-8'), self.server_public_key)
                self.client_socket.send(encrypted_message)
        except Exception as e:
            print(f"Error sending message: {e}")

    def receive_public_key(self):
        try:
            public_key_bytes = self.client_socket.recv(2048)
            self.server_public_key = RSA.import_key(public_key_bytes.decode('utf-8'))
            print("Received server's public key.")

            # Send the client's public key to the server
            self.client_socket.send(self.client_public_key.export_key())
            print("Sent client's public key to the server.")
        except Exception as e:
            print(f"Error during key exchange: {e}")

    def receive_messages(self):
        try:
            while True:
                data = self.client_socket.recv(2048)
                if not data:
                    break
                # Decrypt the received message using the client's private key
                print("client key: " + self.client_public_key.export_key().decode('utf-8'))
                decrypted_message = decrypt_rsa(data, self.client_private_key)
                message = decrypted_message.decode('utf-8')
                print(message)
        except Exception as e:
            print(f"Error receiving message: {e}")

    def start(self):
        try:
            self.client_socket.connect((self.host, self.port))
            print(f"Connected to the server at {self.host}:{self.port}")
            self.client_socket.send(self.username.encode('utf-8'))

            # Receive the server's public key and send the client's public key
            self.receive_public_key()

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

# Example usage
username = input("Enter your Name: ")
client = Client('127.0.0.1', 5555, username)
client.start()
