#!/usr/bin/env python3

from scapy.all import *
import struct

# Define DDS ports to listen on
dds_ports = [7400, 7401]

def parse_rtps_payload(data):
    """Parse RTPS payload data and return a human-readable format."""
    try:
        output = ""
        
        if data[:4] != b'RTPS':
            return "Not a valid RTPS packet\n"
        
        protocol_version = data[4:6]
        vendor_id = data[6:8]
        guid_prefix = data[8:20]

        output += f"Protocol: {data[:4].decode()}, Version: {protocol_version.hex()}, Vendor ID: {vendor_id.hex()}\n"
        output += f"GUID Prefix: {guid_prefix.hex()}\n"
        
        offset = 20
        while offset < len(data):
            submessage_id = data[offset]
            flags = data[offset + 1]
            submessage_length = struct.unpack_from('>H', data, offset + 2)[0]
            submessage_data = data[offset + 4:offset + 4 + submessage_length]

            output += f"\nSubmessage ID: {submessage_id}, Flags: {flags}, Length: {submessage_length}\n"
            
            if submessage_id == 0x15:  # INFO_TS Submessage
                timestamp = struct.unpack_from('>Q', submessage_data, 0)[0]  # Read 8 bytes as unsigned long long
                output += f"INFO_TS Timestamp: {timestamp}\n"
            elif submessage_id == 0x12:  # DATA Submessage
                reader_id = struct.unpack_from('>I', submessage_data, 0)[0]  # Read 4 bytes as unsigned int
                writer_id = struct.unpack_from('>I', submessage_data, 4)[0]
                serialized_payload = submessage_data[8:]  # Rest is payload
                output += f"DATA Reader ID: {reader_id}, Writer ID: {writer_id}\n"
                output += f"Serialized Payload: {serialized_payload}\n"

                # Further detailed parsing of serialized payload
                output += "Parsed Serialized Payload:\n"
                for i in range(0, len(serialized_payload), 4):
                    field_value = struct.unpack_from('>I', serialized_payload, i)[0]
                    output += f"Field {i//4}: {field_value} (0x{field_value:08x})\n"
            else:
                output += f"Unknown Submessage ID: {submessage_id}\n"
                output += f"Raw Submessage Data: {submessage_data}\n"
                
                # Detailed parsing for the unknown submessage
                output += "Detailed Parsing of Raw Submessage Data:\n"
                for i in range(0, len(submessage_data), 4):
                    field_value = struct.unpack_from('>I', submessage_data, i)[0]
                    output += f"Field {i//4}: {field_value} (0x{field_value:08x})\n"
            
            offset += 4 + submessage_length
        
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
