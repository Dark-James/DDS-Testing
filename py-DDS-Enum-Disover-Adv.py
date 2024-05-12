#!/usr/bin/env python3

from scapy.all import sniff, UDP, Raw
import struct
from collections import defaultdict

# Vendor information directly embedded
vendors_info = {
    "0101": {"Vendor Name": "RTI Connext DDS", "Version": "5.3.1", "Vulnerable": "Yes"},
    "0102": {"Vendor Name": "OpenSplice DDS", "Version": "6.9.0", "Vulnerable": "Unknown"},
    "0103": {"Vendor Name": "CoreDX DDS", "Version": "4.1.1", "Vulnerable": "Yes"},
    "0104": {"Vendor Name": "Fast DDS", "Version": "2.3.0", "Vulnerable": "Unknown"},
    "0105": {"Vendor Name": "eProsima DDS", "Version": "1.10.0", "Vulnerable": "Unknown"},
    "0106": {"Vendor Name": "PrismTech Vortex", "Version": "7.0.0", "Vulnerable": "Unknown"},
    "0107": {"Vendor Name": "Twin Oaks CoreDX", "Version": "4.0.0", "Vulnerable": "Unknown"},
    "0108": {"Vendor Name": "OCI OpenDDS", "Version": "3.13.0", "Vulnerable": "Unknown"},
    "0109": {"Vendor Name": "Object Computing", "Version": "6.4.0", "Vulnerable": "Unknown"},
    "0110": {"Vendor Name": "CloudiX DDS", "Version": "5.0.0", "Vulnerable": "Unknown"}
    # Add more vendor details as required
}

# Define RTPS submessage IDs for Data and Info-Source
DATA_SUBMESSAGE_ID = 0x15
INFO_TS_SUBMESSAGE_ID = 0x12

# Parse RTPS payload to extract vendor, version, and GUID information
def parse_rtps_payload(data):
    if data[:4] != b'RTPS':
        return None, None, None
    
    protocol_version = f"{data[4]}.{data[5]}"
    vendor_id = data[6:8].hex()
    guid_prefix = data[8:20].hex()
    
    return vendor_id, protocol_version, guid_prefix

# Packet callback function to process each packet
def packet_callback(pkt, detected_endpoints):
    if UDP in pkt and Raw in pkt:
        raw_data = pkt[Raw].load
        vendor_id, version, guid_prefix = parse_rtps_payload(raw_data)
        
        if vendor_id and guid_prefix:
            vendor_name = vendors_info.get(vendor_id, {}).get('Vendor Name', 'Unknown')
            endpoint_type = "Unknown"
            offset = 20
            
            while offset < len(raw_data):
                submessage_id = raw_data[offset]
                submessage_length = struct.unpack_from('>H', raw_data, offset + 2)[0]
                submessage_data = raw_data[offset + 4:offset + 4 + submessage_length]
                
                if submessage_id == DATA_SUBMESSAGE_ID:
                    endpoint_type = "Publisher"
                elif submessage_id == INFO_TS_SUBMESSAGE_ID:
                    endpoint_type = "Subscriber"
                
                offset += 4 + submessage_length
            
            detected_endpoints[guid_prefix] = {
                'Vendor Name': vendor_name,
                'Version': version,
                'GUID': guid_prefix,
                'Type': endpoint_type
            }

# Main function to start the sniffing and display results
def main():
    detected_endpoints = defaultdict(dict)
    
    print("Starting to sniff DDS packets on the network for 30 seconds...")
    sniff(filter="udp port 7400 or udp port 7401", prn=lambda pkt: packet_callback(pkt, detected_endpoints), timeout=30)
    
    print("\nDetected DDS Endpoints:")
    print("GUID,Vendor Name,Version,Type")
    for guid, info in detected_endpoints.items():
        print(f"{info['GUID']},{info['Vendor Name']},{info['Version']},{info['Type']}")

if __name__ == "__main__":
    main()
