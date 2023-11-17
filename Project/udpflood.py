from scapy.all import IP, UDP, send
import time

try:
    # Get user input for target IP, target port, and number of packets
    target_ip = input("Enter the target IP address: ")
    target_port = int(input("Enter the target port: "))
    num_packets = int(input("Enter the number of packets to send: "))
    msg_to_send = input("Enter a message to send to the target: ")

    # Craft a simple UDP packet
    udp_packet = IP(dst=target_ip) / UDP(dport=target_port) / msg_to_send

    # Send UDP packets in a loop with a small interval
    for _ in range(num_packets):
        send(udp_packet)

except KeyboardInterrupt:
    print("\nUser interrupted. Stopping the script.")
except Exception as e:
    print(f"An error occurred: {e}")
