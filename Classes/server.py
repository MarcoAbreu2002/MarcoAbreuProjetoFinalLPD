import socket
host = "192.168.1.101" #Server address
port = 122 #Port of Server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host,port)) #bind server
s.listen()
(conn, addr) = s.accept()
conn.send("Thank you for connecting".encode())
dataFromClient = conn.recv(1024)
print(dataFromClient.decode())
conn.close()

