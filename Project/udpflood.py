import sys
from scapy.all import IP, UDP, send
import threading
import socket
import re

def send_packet(target_ip, target_port, msg_to_send):
    """
    Function to send a UDP packet to a specified target IP and port with a given message.

    :param target_ip: The target IP address to send the packet to.
    :type target_ip: str
    :param target_port: The target port to send the packet to.
    :type target_port: int
    :param msg_to_send: The message to be sent in the packet.
    :type msg_to_send: str
    """
    udp_packet = IP(dst=target_ip) / UDP(dport=target_port) / msg_to_send
    try:
        send(udp_packet, verbose=False)
    except Exception as e:
        print(f"Error sending packet to {target_ip}:{target_port}: {e}")
        sys.exit(1)  # Exit the program immediately upon encountering an exception

try:
    # Get user input for target IP, target port, and number of packets
    target_ip = input("Enter the target IP address: ")
    
    # Validate the target IP address format
    ip_format_regex = r'^(\d{1,3}\.){3}\d{1,3}$'  # Regular expression pattern for IPv4 address
    if not re.match(ip_format_regex, target_ip):
        print("Invalid IP address format. Please enter a valid IP address.")
        sys.exit(1)

    target_port = int(input("Enter the target port: "))
    num_packets = int(input("Enter the number of packets to send: "))
    msg_to_send = input("Enter a message to send to the target: ")

    # Timeout for connection (in seconds)
    timeout_seconds = 5  

    # Create a thread for each packet and start them concurrently
    threads = []
    for _ in range(num_packets):
        thread = threading.Thread(target=send_packet, args=(target_ip, target_port, msg_to_send))
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish or timeout
    for thread in threads:
        thread.join(timeout_seconds)

except KeyboardInterrupt:
    print("\nUser interrupted. Stopping the script.")
    sys.exit(0)  # Exit the program gracefully upon user interrupt
except Exception as e:
    print(f"An error occurred: {e}")
    sys.exit(1)  # Exit the program immediately upon encountering an exception
