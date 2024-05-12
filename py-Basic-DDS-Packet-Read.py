#!/usr/bin/env python3

from scapy.all import *
import struct

# Define DDS ports to listen on
dds_ports = [7400, 7401]

def parse_rtps_payload(data):
    """Parse RTPS payload data and return a human-readable format."""
    try:
        output = ""
        # Basic interpretation of the RTPS Header (Submessage ID, Flags, Length)
        submessage_id = data[0]
        flags = data[1]
        length = struct.unpack_from('>H', data, 2)[0]  # Read 2 bytes as unsigned short
        
        output += f"Submessage ID: {submessage_id}, Flags: {flags}, Length: {length}\n"

        # Continue parsing based on submessage type (this is a simplified example)
        if submessage_id == 0x15:  # INFO_TS Submessage
            timestamp = struct.unpack_from('>Q', data, 4)[0]  # Read 8 bytes as unsigned long long
            output += f"INFO_TS Timestamp: {timestamp}\n"
        elif submessage_id == 0x12:  # DATA Submessage
            reader_id = struct.unpack_from('>I', data, 4)[0]  # Read 4 bytes as unsigned int
            writer_id = struct.unpack_from('>I', data, 8)[0]
            output += f"DATA Reader ID: {reader_id}, Writer ID: {writer_id}\n"
            serialized_payload = data[16:]  # Rest is payload
            output += f"Serialized Payload: {serialized_payload}\n"
        else:
            output += f"Unknown Submessage ID: {submessage_id}\n"
            output += f"Raw Payload: {data}\n"
        
        return output
    except Exception as e:
        return f"Error parsing payload: {e}\n"

def packet_callback(pkt):
    if UDP in pkt and pkt[UDP].dport in dds_ports:
        print("Captured a DDS packet:")
        pkt.show()
        if Raw in pkt:
            raw_data = pkt[Raw].load
            print("RTPS Payload Interpretation:")
            print(parse_rtps_payload(raw_data))

if __name__ == "__main__":
    print("Starting to sniff DDS packets...")
    sniff(filter="udp port 7400 or udp port 7401", prn=packet_callback, store=0)
