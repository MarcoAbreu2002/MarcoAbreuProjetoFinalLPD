import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1" # server address
port = 123 #server port
s.connect((host,port))
dataFromServer = s.recv(1024)
print(dataFromServer.decode())
dataToServer = "Hello Server From Client"
s.send(dataToServer.encode())
s.close()
