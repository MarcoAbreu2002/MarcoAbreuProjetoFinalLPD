import time
import telnetlib
import subprocess
import paramiko

def knock_sequence(ip_address, sequence):
    """
    This method receives a remote ip_address and a sequence. Then
    according to the sequence it creates telnet knocks.
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
    command = f"sshpass -p '{password}' ssh {username}@{hostname}"
    print(f"Tentando conectar via SSH: {command}")
    subprocess.call(command, shell=True)


def install_packages():
    packages = ["network-manager-l2tp"]
    subprocess.run(["sudo", "apt", "update"])
    subprocess.run(["sudo", "apt", "install", "-y"] + packages)

def establish_L2TP_IPSEC_connection(server_ip, pre_shared_key,username, password):
    # Step 1: Create L2TP options file
    l2tp_options = """
    lock
    noauth
    refuse-eap
    refuse-pap
    refuse-chap
    refuse-mschap
    nobsdcomp
    nodeflate
    require-mschap-v2
    name {username}
    password {password}
    """
    with open('/etc/ppp/options.l2tpd.client', 'w') as f:
        f.write(l2tp_options.format(username=username, password=password))

    # Step 2: Start the VPN connection
    subprocess.run(['sudo', 'ipsec', 'up', 'myvpn'], check=True)
    subprocess.run(['sudo', 'echo', 'c myvpn', '|', 'sudo', 'tee', '/var/run/xl2tpd/l2tp-control'], shell=True, check=True)
    time.sleep(2)  # Wait for the connection to establish

    # Step 3: Add the route
    subprocess.run(['sudo', 'ip', 'route', 'add', vpn_server_ip, 'dev', 'ppp0'], check=True)







def main():
    ip_address = input("Enter the IP address you want to connect to: ")
    sequence_str = input("Enter the door knocking sequence for SSH (comma-separated ports): ")
    sequence_ssh = [int(port.strip()) for port in sequence_str.split(',')]

    #sequence_str = input("Enter the door knocking sequence for L2TP/IPSec (comma-separated ports): ")
    #sequence_l2tp_ipsec = [int(port.strip()) for port in sequence_str.split(',')]

    knock_sequence(ip_address, sequence_ssh)
    #knock_sequence(ip_address, sequence_ssh)

    username = input("Enter your SSH username: ")
    password = input("Enter your SSH password: ")
    establish_ssh_connection(ip_address, username, password)
    pre_shared_key = input("Enter the pre-shared key: ")
    install_packages()
    establish_L2TP_IPSEC_connection(ip_address, pre_shared_key ,username, password)

if __name__ == "__main__":
    main()

