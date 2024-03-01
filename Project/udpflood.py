from scapy.all import IP, UDP, send
import threading

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
    send(udp_packet)

try:
    # Get user input for target IP, target port, and number of packets
    target_ip = input("Enter the target IP address: ")
    target_port = int(input("Enter the target port: "))
    num_packets = int(input("Enter the number of packets to send: "))
    msg_to_send = input("Enter a message to send to the target: ")

    # Create a thread for each packet and start them concurrently
    threads = []
    for _ in range(num_packets):
        thread = threading.Thread(target=send_packet, args=(target_ip, target_port, msg_to_send))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

except KeyboardInterrupt:
    print("\nUser interrupted. Stopping the script.")
except Exception as e:
    print(f"An error occurred: {e}")
