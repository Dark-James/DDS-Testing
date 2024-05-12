#!/usr/bin/env python3

import curses
from scapy.all import *
import struct
import itertools

# Define DDS ports to listen on
dds_ports = [7400, 7401]

# Global variable to store the screen object
stdscr = None

def parse_rtps_payload(data):
    """Parse RTPS payload data and return a list of fields and a human-readable format."""
    fields = []
    output = ""
    try:
        if data[:4] != b'RTPS':
            return fields, "Not a valid RTPS packet\n"
        
        protocol_version = data[4:6]
        vendor_id = data[6:8]
        guid_prefix = data[8:20]

        output += f"Protocol: {data[:4].decode()}, Version: {protocol_version.hex()}, Vendor ID: {vendor_id.hex()}\n"
        output += f"GUID Prefix: {guid_prefix.hex()}\n"
        
        fields.append(('Protocol', data[:4].decode()))
        fields.append(('Version', protocol_version.hex()))
        fields.append(('Vendor ID', vendor_id.hex()))
        fields.append(('GUID Prefix', guid_prefix.hex()))
        
        offset = 20
        while offset < len(data):
            submessage_id = data[offset]
            flags = data[offset + 1]
            submessage_length = struct.unpack_from('>H', data, offset + 2)[0]
            submessage_data = data[offset + 4:offset + 4 + submessage_length]

            output += f"\nSubmessage ID: {submessage_id}, Flags: {flags}, Length: {submessage_length}\n"
            fields.append(('Submessage ID', submessage_id))
            fields.append(('Flags', flags))
            fields.append(('Length', submessage_length))
            
            if submessage_id == 0x15:  # INFO_TS Submessage
                timestamp = struct.unpack_from('>Q', submessage_data, 0)[0]  # Read 8 bytes as unsigned long long
                output += f"INFO_TS Timestamp: {timestamp}\n"
                fields.append(('INFO_TS Timestamp', timestamp))
            elif submessage_id == 0x12:  # DATA Submessage
                reader_id = struct.unpack_from('>I', submessage_data, 0)[0]  # Read 4 bytes as unsigned int
                writer_id = struct.unpack_from('>I', submessage_data, 4)[0]
                serialized_payload = submessage_data[8:]  # Rest is payload
                output += f"DATA Reader ID: {reader_id}, Writer ID: {writer_id}\n"
                output += f"Serialized Payload: {serialized_payload}\n"
                fields.append(('Reader ID', reader_id))
                fields.append(('Writer ID', writer_id))

                # Further detailed parsing of serialized payload
                output += "Parsed Serialized Payload:\n"
                for i in range(0, len(serialized_payload), 4):
                    field_value = struct.unpack_from('>I', serialized_payload, i)[0]
                    output += f"Field {i//4}: {field_value} (0x{field_value:08x})\n"
                    fields.append((f'Serialized Field {i//4}', field_value))
            else:
                output += f"Unknown Submessage ID: {submessage_id}\n"
                output += f"Raw Submessage Data: {submessage_data}\n"
                
                # Detailed parsing for the unknown submessage
                output += "Detailed Parsing of Raw Submessage Data:\n"
                for i in range(0, len(submessage_data), 4):
                    field_value = struct.unpack_from('>I', submessage_data, i)[0]
                    output += f"Field {i//4}: {field_value} (0x{field_value:08x})\n"
                    fields.append((f'Unknown Field {i//4}', field_value))
            
            offset += 4 + submessage_length
        
        # Exclude Protocol, Version, and IDs from fields to be fuzzed
        fields = [f for f in fields if f[0] not in ['Protocol', 'Version', 'Submessage ID', 'Reader ID', 'Writer ID']]
        
        return fields, output
    except Exception as e:
        return fields, f"Error parsing payload: {e}\n"

def fuzz_field_combinations(fields):
    """Generate pairwise fuzzing combinations for given fields."""
    fuzzed_outputs = []
    field_names = [name for name, _ in fields]
    field_values = [value for _, value in fields]

    # Generate pairwise combinations
    for (i, j) in itertools.combinations(range(len(field_values)), 2):
        fuzzed_field_output = ""
        fuzzed_field_output += f"\nFuzzing Fields: {field_names[i]} and {field_names[j]}\n"
        for value_i in range(0, 256, 64):  # Increase step to 64 for speed
            for value_j in range(0, 256, 64):  # Increase step to 64 for speed
                fuzzed_values = field_values[:]
                fuzzed_values[i] = value_i
                fuzzed_values[j] = value_j
                fuzzed_field_output += f"Fuzzed {field_names[i]}: {value_i}, {field_names[j]}: {value_j} -> {fuzzed_values}\n"
        fuzzed_outputs.append(fuzzed_field_output)
    
    return fuzzed_outputs

def display_packet_info(stdscr, fields, dissection_output, fuzzed_outputs):
    """Display the packet dissection and fuzzing info side by side."""
    stdscr.clear()
    height, width = stdscr.getmaxyx()

    dissection_lines = dissection_output.split('\n')
    fuzzing_lines = "\n".join(fuzzed_outputs).split('\n')

    max_lines = max(len(dissection_lines), len(fuzzing_lines))

    for i in range(max_lines):
        if i < len(dissection_lines):
            stdscr.addstr(i, 0, dissection_lines[i][:width//2 - 1])
        if i < len(fuzzing_lines):
            stdscr.addstr(i, width//2, fuzzing_lines[i][:width//2 - 1])

    stdscr.refresh()

def packet_callback(pkt):
    try:
        if UDP in pkt and pkt[UDP].dport in dds_ports:
            global stdscr
            if Raw in pkt:
                raw_data = pkt[Raw].load
                fields, dissection_output = parse_rtps_payload(raw_data)
                fuzzed_outputs = fuzz_field_combinations(fields)
                display_packet_info(stdscr, fields, dissection_output, fuzzed_outputs)
    except Exception as e:
        if stdscr:
            stdscr.addstr(0, 0, f"Error processing packet: {e}")
            stdscr.refresh()

def main(stdscr_obj):
    global stdscr
    stdscr = stdscr_obj
    stdscr.nodelay(True)
    curses.curs_set(0)  # Hide cursor
    stdscr.clear()
    stdscr.addstr(0, 0, "Starting to sniff DDS packets...")
    stdscr.refresh()
    
    try:
        sniff(filter="udp port 7400 or udp port 7401", prn=packet_callback, store=0)
    except Exception as e:
        stdscr.addstr(1, 0, f"Sniffing error: {e}")
        stdscr.refresh()
        stdscr.getch()

if __name__ == "__main__":
    curses.wrapper(main)
