#!/usr/bin/env python3

from scapy.all import sniff, UDP, Raw
import struct
from collections import defaultdict

# Vendor information directly embedded from the CSV
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

# Parse RTPS payload to extract vendor and version information
def parse_rtps_payload(data):
    if data[:4] != b'RTPS':
        return None
    
    vendor_id = data[6:8].hex()
    version = f"{data[4]}.{data[5]}"
    return vendor_id, version

# Packet callback function to process each packet
def packet_callback(pkt, detected_vendors):
    if UDP in pkt and Raw in pkt:
        raw_data = pkt[Raw].load
        parsed_info = parse_rtps_payload(raw_data)
        if parsed_info:
            vendor_id, version = parsed_info
            if vendor_id in vendors_info:
                vendor_name = vendors_info[vendor_id]['Vendor Name']
                known_vulnerable = vendors_info[vendor_id]['Vulnerable'] == "Yes"
                detected_vendors[vendor_id] = {
                    'Vendor Name': vendor_name,
                    'Version': version,
                    'Vulnerable': "Yes" if known_vulnerable else "Unknown"
                }

# Main function to start the sniffing and display results
def main():
    detected_vendors = defaultdict(dict)
    
    print("Starting to sniff DDS packets for 10 seconds...")
    sniff(filter="udp port 7400 or udp port 7401", prn=lambda pkt: packet_callback(pkt, detected_vendors), timeout=10)
    
    print("\nDetected DDS Traffic:")
    print("Vendor ID,Vendor Name,Version,Vulnerable")
    for vendor_id, info in detected_vendors.items():
        print(f"{vendor_id},{info['Vendor Name']},{info['Version']},{info['Vulnerable']}")

if __name__ == "__main__":
    main()
