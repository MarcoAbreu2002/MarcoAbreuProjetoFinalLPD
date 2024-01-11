import socket
import threading

class Client:
    def __init__(self, host, port, username):
        self.host = host
        self.port = port
        self.username = username
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send_message(self):
        try:
            while True:
                message = input("Digite sua mensagem: ")
                self.client_socket.send(message.encode('utf-8'))
        except Exception as e:
            print(f"Erro ao enviar mensagem: {e}")

    def receive_messages(self):
        try:
            while True:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                message = data.decode('utf-8')
                print(message)
        except Exception as e:
            print(f"Erro ao receber mensagem: {e}")

    def start(self):
        try:
            self.client_socket.connect((self.host, self.port))
            print(f"Conectado ao servidor em {self.host}:{self.port}")
            self.client_socket.send(self.username.encode('utf-8'))

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
client = Client('127.0.0.1', 5555, username)
client.start()
