import time
import telnetlib
import subprocess
import paramiko

def knock_sequence(ip_address, sequence):
    """
    Knock on a sequence of ports using Telnet.

    :param ip_address: The IP address of the remote server.
    :type ip_address: str
    :param sequence: A list of port numbers to knock on.
    :type sequence: list[int]
    """
    # Knock on the sequence of ports using Telnet
    for port in sequence:
        try:
            tn = telnetlib.Telnet(ip_address, port)
            tn.close()
            print(f"Knocked on port {port}")
        except ConnectionRefusedError:
            print(f"Port {port} is closed, skipping...")

def establish_ssh_connection(hostname, username, password):
    """
    Establish an SSH connection to a remote host.

    :param hostname: The hostname or IP address of the remote server.
    :type hostname: str
    :param username: The SSH username.
    :type username: str
    :param password: The SSH password.
    :type password: str
    """
    command = f"sshpass -p '{password}' ssh {username}@{hostname}"
    print(f"Tentando conectar via SSH: {command}")
    subprocess.call(command, shell=True)


def install_packages():
    """
    Install required packages using apt.
    """
    packages = ["network-manager-l2tp"]
    subprocess.run(["sudo", "apt", "update"])
    subprocess.run(["sudo", "apt", "install", "-y"] + packages)

def establish_L2TP_IPSEC_connection(server_ip, pre_shared_key,username, password):
     """
    Establish an L2TP/IPSec VPN connection.

    :param server_ip: The IP address of the VPN server.
    :type server_ip: str
    :param pre_shared_key: The pre-shared key for IPSec.
    :type pre_shared_key: str
    :param username: The VPN username.
    :type username: str
    :param password: The VPN password.
    :type password: str
    """
    # Step 1: Create L2TP options file
   # l2tp_options = "2"
   # with open('/etc/ppp/options.l2tpd.client', 'w') as f:
   #     f.write(l2tp_options.format(username=username, password=password))

    # Step 2: Start the VPN connection
    #subprocess.run(['sudo', 'ipsec', 'up', 'myvpn'], check=True)
    #subprocess.run(['sudo', 'echo', 'c myvpn', '|', 'sudo', 'tee', '/var/run/xl2tpd/l2tp-control'], shell=True, check=True)
    #time.sleep(2)  # Wait for the connection to establish

    # Step 3: Add the route
   # subprocess.run(['sudo', 'ip', 'route', 'add', vpn_server_ip, 'dev', 'ppp0'], check=True)







def main():
    ip_address = "1"  #input("Enter the IP address you want to connect to: ")
    sequence_str = "2" #input("Enter the door knocking sequence for SSH (comma-separated ports): ")
    sequence_ssh = [int(port.strip()) for port in sequence_str.split(',')]

    #sequence_str = input("Enter the door knocking sequence for L2TP/IPSec (comma-separated ports): ")
    #sequence_l2tp_ipsec = [int(port.strip()) for port in sequence_str.split(',')]

    #knock_sequence(ip_address, sequence_ssh)
    #knock_sequence(ip_address, sequence_ssh)

    username = "e" #input("Enter your SSH username: ")
    password = "2" #input("Enter your SSH password: ")
    #establish_ssh_connection(ip_address, username, password)
    pre_shared_key = "q" #input("Enter the pre-shared key: ")
    #install_packages()
    #establish_L2TP_IPSEC_connection(ip_address, pre_shared_key ,username, password)

if __name__ == "__main__":
    main()

