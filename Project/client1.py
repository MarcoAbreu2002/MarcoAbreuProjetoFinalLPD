import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from integrity import generate_digest, verify_digest
from encryption import generate_key_pair, encrypt_rsa, decrypt_rsa

class Client:
    def __init__(self, host, port, username):
        self.host = host
        self.port = port
        self.username = username
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_private_key, self.client_public_key = generate_key_pair()  # Generate and store the client's key pair
        self.server_public_key = None
        self.mac_key = None

    def send_message(self):
        try:
            while True:
                message = input("Enter your message: ")
                encrypted_message = encrypt_rsa(message.encode('utf-8'), self.server_public_key)
                # Generate digest for the message
                digest_to_send = generate_digest(encrypted_message, self.mac_key, 'sha256')
                # Attach both the message and the digest when sending
                #print("Encrypted message: " + encrypted_message.hex())
                data_to_send = encrypted_message + b' : ' + digest_to_send
                self.client_socket.send(data_to_send)
        except Exception as e:
            print(f"Error sending message: {e}")

    def receive_public_key_and_mac_key(self):
        try:
            public_key_bytes = self.client_socket.recv(2048)
            self.server_public_key = RSA.import_key(public_key_bytes.decode('utf-8'))
            print("Received server's public key.")
            # Send the client's public key to the server
            self.client_socket.send(self.client_public_key.export_key())
            print("Sent client's public key to the server.")
            # Receive the encrypted MAC key from the server
            encrypted_mac_key = self.client_socket.recv(2048)
            # Decrypt the received MAC key using the client's private key
            self.mac_key = decrypt_rsa(encrypted_mac_key, self.client_private_key)
            print(f"Received and decrypted MAC key from the server: {self.mac_key.hex()}")

        except Exception as e:
            print(f"Error during key exchange: {e}")

    def receive_messages(self):
        try:
            while True:
                data = self.client_socket.recv(2048)
                if not data:
                    break
                # Separate message and digest
                message, received_digest = data.split(b' : ')

                generated_digest = generate_digest(message,self.mac_key,'sha256')
                # Verify the integrity of the received message
                is_integrity_verified = verify_digest(received_digest, generated_digest)

                if is_integrity_verified:
                    print("Integrity verified")
                    # Decrypt the received message using the client's private key
                    decrypted_message = decrypt_rsa(message, self.client_private_key)
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

# Example usage
username = input("Enter your Name: ")
client = Client('127.0.0.1', 5555, username)
client.start()
