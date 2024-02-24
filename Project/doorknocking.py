import paramiko
import telnetlib

def knock_sequence(ip_address, sequence):
    # Knock on the sequence of ports using Telnet
    for port in sequence:
        try:
            tn = telnetlib.Telnet(ip_address, port)
            tn.close()
            print(f"Knocked on port {port}")
        except ConnectionRefusedError:
            print(f"Port {port} is closed, skipping...")

def establish_ssh_connection(hostname, username, password):
    # Create SSH client
    ssh = paramiko.SSHClient()

    # Automatically add untrusted hosts
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to the host
        ssh.connect(hostname, username=username, password=password)

        print("Connected to", hostname)

        # Keep the connection open until the user types "exit"
        while True:
            command = input("$ ")
            if command.lower() == "exit":
                break
            stdin, stdout, stderr = ssh.exec_command(command)
            for line in stdout:
                print(line.strip())

        # Close the connection
        ssh.close()
        print("SSH connection closed.")

    except paramiko.AuthenticationException:
        print("Authentication failed, please check your credentials.")
    except paramiko.SSHException as e:
        print("Unable to establish SSH connection:", str(e))
    except Exception as e:
        print("Error:", str(e))

def main():
    ip_address = input("Enter the IP address you want to connect to: ")
    sequence_str = input("Enter the door knocking sequence (comma-separated ports): ")
    sequence = [int(port.strip()) for port in sequence_str.split(',')]

    knock_sequence(ip_address, sequence)

    # Assume you want to establish SSH using password authentication
    username = input("Enter your SSH username: ")
    password = input("Enter your SSH password: ")

    establish_ssh_connection(ip_address, username, password)

if __name__ == "__main__":
    main()

