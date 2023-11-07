import socket

def scan_ports(ip, ports, s):
    open_ports = []  # Place the available ports in an array
    for port in ports:
        try:
            s.settimeout(1)
            s.connect((ip, port))
            open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError):
            pass
        except Exception as e:
            pass
    return open_ports

remote_ip ="127.0.0.1"    #input("Insert the ip to scan: ")
port_range = range(1,1025)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
open_ports = scan_ports(remote_ip, port_range,s)

if open_ports:
        print(f"Open ports on {remote_ip}: {open_ports}")
else:
        print(f"No open ports found on {remote_ip}")
