import socket
import os
import threading

def receive_messages(client_socket):
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
            message = data.decode('utf-8')
            print(message)
        except ConnectionResetError:
            print("Connection to the server closed.")
            break

def send_messages(client_socket, username):
    while True:
        try:
            # Prompt the user to insert their message
            message = input()
            #os.system('clear')
            print("\033[F\033[K",end = "",flush = True)
            # Check if the user wants to exit
            if message.lower() == "exit":
                print("Exiting chat...")
                client_socket.close()
                break

            full_message = f"{message}"
            client_socket.send(full_message.encode('utf-8'))

        except KeyboardInterrupt:
            print("\nExiting chat due to Ctrl+C...")
            client_socket.close()
            break

print("*********************************************")
print("**            Encrypted Chat               **")
print("**         Write 'exit' to leave           **")
print("*********************************************")
# Client setup
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get the username from the user
username = input("Enter your name: ")

# Connect to the server
client.connect(('127.0.0.1', 5555))

# Send the username to the server
client.send(username.encode('utf-8'))

# Start separate threads for receiving and sending messages
receive_thread = threading.Thread(target=receive_messages, args=(client,))
send_thread = threading.Thread(target=send_messages, args=(client, username))

receive_thread.start()
send_thread.start()
