import socket
import threading
import select

# Function to handle each client
def handle_client(client_socket, address):
    # Receive the username from the client
    username = client_socket.recv(1024).decode('utf-8')
    print(f"{address} connected with username: {username}")

    while True:
        try:
            # Use select to check for incoming data on the socket
            ready_to_read, _, _ = select.select([client_socket], [], [], 1)

            if ready_to_read:
                data = client_socket.recv(1024)
                if not data:
                    print(f"Connection with {address} closed.")
                    break
                message = data.decode('utf-8')
                print(f"Received message from {username}: {message}")

                # Broadcast the message to all connected clients
                broadcast(f"{username}",f"{message}", client_socket)

        except ConnectionResetError:
            print(f"Connection with {address} reset by client.")
            break

    # Close the client socket
    client_socket.close()

# Function to broadcast messages to all clients
def broadcast(username, message, sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                message = username + ': ' + message
                client.send(message.encode('utf-8'))
            except:
                # Remove the broken connection
                remove_client(client)
        else:
            try:
                message = 'me: ' + message
                client.send(message.encode('utf-8'))
            except:
                # Remove the broken connection
                remove_client(client)



# Function to remove a client from the list
def remove_client(client_socket):
    if client_socket in clients:
        clients.remove(client_socket)

# Server setup
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 5555))
server.listen(5)
print("Server listening on port 5555")

# List to store connected clients
clients = []

# Main server loop
while True:
    try:
        client_socket, client_address = server.accept()
        print(f"Accepted connection from {client_address}")

        # Add the new client to the list
        clients.append(client_socket)

        # Create and start a new thread to handle the client
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

    except KeyboardInterrupt:
        print("\nServer shutting down...")
        # Close all client sockets
        for client_socket in clients:
            client_socket.close()
        # Close the server socket
        server.close()
        break
