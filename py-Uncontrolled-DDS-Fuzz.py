#!/usr/bin/env python3

from scapy.all import *
import time
import random
import string

# Define multicast IP and ports to scan
multicast_ip = "239.255.0.1"  # Typical multicast address for DDS
dds_ports = [7400, 7401]

def generate_random_payload(length=20):
    """Generate a random payload of given length."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length)).encode()

def fuzz_dds():
    print("Starting DDS fuzzing...")

    while True:
        for target_port in dds_ports:
            payload = generate_random_payload()
            packet = IP(dst=multicast_ip) / UDP(dport=target_port) / Raw(load=payload)
            print(f"Fuzzing with packet to {packet[IP].dst}:{packet[UDP].dport} with payload: {payload}")
            try:
                send(packet, verbose=0)
            except PermissionError as e:
                print(f"PermissionError: {e}. Try running the script with elevated privileges (e.g., sudo).")
                return
        time.sleep(1)  # Adjust delay as needed

def packet_callback(pkt):
    if UDP in pkt and pkt[UDP].dport in dds_ports:
        print("Captured a packet from DDS:")
        pkt.show()
        if Raw in pkt:
            raw_data = pkt[Raw].load
            print(f"Raw data: {raw_data}")

if __name__ == "__main__":
    print("Sniffing for DDS responses...")
    sniff(filter="udp dst port 7400 or udp dst port 7401", prn=packet_callback, store=0, timeout=0, stop_filter=lambda x: False)

    # Start fuzzing in a loop
    fuzz_dds()
