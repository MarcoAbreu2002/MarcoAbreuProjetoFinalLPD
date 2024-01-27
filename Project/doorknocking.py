import socket
import time
import paramiko

def knock_sequence(ip, ports):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect((ip, port))
                print(f"Knock on port {port}")
            except socket.error:
                pass
            time.sleep(1)

# Solicitar o endereço IP ao usuário
ip_address = input("Digite o endereço IP da máquina alvo: ")

# Solicitar o nome de usuário e senha ao usuário
username = input("Digite o nome de usuário SSH: ")
password = input("Digite a senha SSH: ")

# Definir a sequência desejada de portas
port_sequence = [1000, 2000, 3000]

# Chamar a função para realizar a sequência de port knocking
knock_sequence(ip_address, port_sequence)

# Conectar-se via SSH após a sequência correta
try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # Conectar com os dados fornecidos pelo usuário
    ssh.connect(ip_address, port=22, username=username, password=password)

    print("Conexão SSH bem-sucedida!")
    # Adicione aqui o código para interagir com a sessão SSH, se necessário

except Exception as e:
    print(f"Erro na conexão SSH: {e}")

finally:
    # Fechar a conexão SSH, se estiver aberta
    if ssh:
        ssh.close()
