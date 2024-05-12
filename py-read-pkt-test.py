#!/usr/bin/env python3

from scapy.all import *

def scan_dds():
    print("Starting DDS scan...")

    # Define the destination IP and port
    target_ip = "127.0.0.1"
    target_port = 7400

    # Construct the DDS packet with typical parameters
    packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load="Custom DDS Payload")

    print(f"Sending packet to {packet[IP].dst}:{packet[UDP].dport} with payload: {packet[Raw].load}")

    # Send the packet
    send(packet, verbose=2)

    # Sniff for incoming responses on port 7400
    def packet_callback(pkt):
        if UDP in pkt and pkt[UDP].dport == target_port:
            print("Captured a packet:")
            pkt.show()
            if Raw in pkt:
                raw_data = pkt[Raw].load
                print(f"Raw data: {raw_data}")

    print("Sniffing for responses...")
    sniff(filter="udp port 7400", prn=packet_callback, timeout=10)

if __name__ == "__main__":
    scan_dds()
