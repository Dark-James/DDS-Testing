#!/usr/bin/env python3

from scapy.all import *
import time

# Define multicast IP and ports to scan
multicast_ip = "239.255.0.1"  # Typical multicast address for DDS
dds_ports = [7400, 7401]

def scan_dds():
    print("Starting continuous DDS scan...")

    # Construct and send DDS packets for each target port
    for target_port in dds_ports:
        packet = IP(dst=multicast_ip) / UDP(dport=target_port) / Raw(load="Custom DDS Payload")
        print(f"Sending packet to {packet[IP].dst}:{packet[UDP].dport} with payload: {packet[Raw].load}")
        try:
            send(packet, verbose=0)
        except PermissionError as e:
            print(f"PermissionError: {e}. Try running the script with elevated privileges (e.g., sudo).")
            return

    # Sniff for incoming responses on specified ports
    def packet_callback(pkt):
        if UDP in pkt and pkt[UDP].dport in dds_ports:
            print("Captured a packet from DDS:")
            pkt.show()
            if Raw in pkt:
                raw_data = pkt[Raw].load
                print(f"Raw data: {raw_data}")

            # Check for specific DDS publisher/subscriber patterns in raw data
            if b'PUBLISHER' in raw_data:
                print("Found a DDS Publisher!")
            elif b'SUBSCRIBER' in raw_data:
                print("Found a DDS Subscriber!")
            else:
                print("Found a DDS entity, but type is unknown.")

    print("Sniffing for responses...")
    sniff(filter=f"udp dst port 7400 or udp dst port 7401", prn=packet_callback, store=0, timeout=10)

if __name__ == "__main__":
    while True:
        scan_dds()
        time.sleep(5)  # Adjust the delay as needed
