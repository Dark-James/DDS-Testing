#!/usr/bin/env python3

from scapy.all import *
import struct
import curses
from collections import defaultdict

# Define DDS ports to listen on
dds_ports = [7400, 7401]

# Initialize dictionaries to track highest and lowest values and previous raw data
field_values = defaultdict(lambda: {"min": float('inf'), "max": float('-inf'), "min_changed": False, "max_changed": False})
previous_raw_data = None

def update_extremes(field_name, value):
    """Update the highest and lowest values and track changes."""
    field_values[field_name]["min_changed"] = False
    field_values[field_name]["max_changed"] = False
    
    if value < field_values[field_name]["min"]:
        field_values[field_name]["min"] = value
        field_values[field_name]["min_changed"] = True
    if value > field_values[field_name]["max"]:
        field_values[field_name]["max"] = value
        field_values[field_name]["max_changed"] = True

def parse_rtps_payload(data):
    """Parse RTPS payload data and return a dictionary of parsed values."""
    parsed_data = {}
    
    if data[:4] != b'RTPS':
        parsed_data["Error"] = "Not a valid RTPS packet"
        return parsed_data
    
    protocol_version = data[4:6]
    vendor_id = data[6:8]
    guid_prefix = data[8:20]

    parsed_data["Protocol"] = data[:4].decode()
    parsed_data["Version"] = protocol_version.hex()
    parsed_data["Vendor ID"] = vendor_id.hex()
    parsed_data["GUID Prefix"] = guid_prefix.hex()
    
    offset = 20
    while offset < len(data):
        if offset + 4 > len(data):
            break
        
        submessage_id = data[offset]
        flags = data[offset + 1]
        if offset + 4 + 2 > len(data):
            break
        submessage_length = struct.unpack_from('>H', data, offset + 2)[0]
        submessage_data = data[offset + 4:offset + 4 + submessage_length]

        submessage_info = {
            "Submessage ID": submessage_id,
            "Flags": flags,
            "Length": submessage_length
        }
        
        if submessage_id == 0x15:  # INFO_TS Submessage
            if len(submessage_data) >= 8:
                timestamp = struct.unpack_from('>Q', submessage_data, 0)[0]  # Read 8 bytes as unsigned long long
                submessage_info["INFO_TS Timestamp"] = timestamp
        elif submessage_id == 0x12:  # DATA Submessage
            if len(submessage_data) >= 8:
                reader_id = struct.unpack_from('>I', submessage_data, 0)[0]  # Read 4 bytes as unsigned int
                writer_id = struct.unpack_from('>I', submessage_data, 4)[0]
                serialized_payload = submessage_data[8:]  # Rest is payload
                submessage_info["DATA Reader ID"] = reader_id
                submessage_info["DATA Writer ID"] = writer_id
                submessage_info["Serialized Payload"] = serialized_payload

                # Further detailed parsing of serialized payload
                fields = {}
                for i in range(0, len(serialized_payload), 4):
                    if i + 4 <= len(serialized_payload):
                        field_value = struct.unpack_from('>I', serialized_payload, i)[0]
                        field_name = f"Field {i//4}"
                        fields[field_name] = field_value
                submessage_info["Parsed Serialized Payload"] = fields
        else:
            submessage_info["Unknown Submessage ID"] = submessage_id
            submessage_info["Raw Submessage Data"] = submessage_data
            
            # Detailed parsing for the unknown submessage
            fields = {}
            for i in range(0, len(submessage_data), 4):
                if i + 4 <= len(submessage_data):
                    field_value = struct.unpack_from('>I', submessage_data, i)[0]
                    field_name = f"Field {i//4}"
                    fields[field_name] = field_value
            submessage_info["Detailed Parsing of Raw Submessage Data"] = fields
        
        parsed_data[f"Submessage {offset//4}"] = submessage_info
        offset += 4 + submessage_length
    
    return parsed_data

def packet_callback(pkt, stdscr):
    if UDP in pkt and pkt[UDP].dport in dds_ports:
        if Raw in pkt:
            raw_data = pkt[Raw].load
            parsed_data = parse_rtps_payload(raw_data)
            update_screen(stdscr, parsed_data, raw_data)

def update_screen(stdscr, parsed_data, raw_data):
    global previous_raw_data
    stdscr.clear()
    row = 0
    max_y, max_x = stdscr.getmaxyx()

    for key, value in parsed_data.items():
        if row >= max_y - 1:
            break
        if isinstance(value, dict):
            stdscr.addstr(row, 0, f"{key}:", curses.A_BOLD)
            row += 1
            for sub_key, sub_value in value.items():
                if row >= max_y - 1:
                    break
                if isinstance(sub_value, dict):
                    stdscr.addstr(row, 2, f"{sub_key}:", curses.A_UNDERLINE)
                    row += 1
                    for field, field_value in sub_value.items():
                        if row >= max_y - 1:
                            break
                        update_extremes(field, field_value)
                        min_val = field_values[field]["min"]
                        max_val = field_values[field]["max"]
                        min_changed = field_values[field]["min_changed"]
                        max_changed = field_values[field]["max_changed"]
                        
                        color_pair_min = 3 if min_changed else 1  # Yellow if changed, else green
                        color_pair_max = 3 if max_changed else 2  # Yellow if changed, else red
                        
                        stdscr.addstr(row, 4, f"{field}: {field_value} (0x{field_value:08x}) ")
                        stdscr.addstr(f"Min: {min_val} (0x{min_val:08x})", curses.color_pair(color_pair_min))
                        stdscr.addstr(", ")
                        stdscr.addstr(f"Max: {max_val} (0x{max_val:08x})", curses.color_pair(color_pair_max))
                        row += 1
                else:
                    line = f"{sub_key}: {sub_value}"
                    if len(line) > max_x - 1:
                        line = line[:max_x - 1]
                    stdscr.addstr(row, 2, line)
                    row += 1
        else:
            line = f"{key}: {value}"
            if len(line) > max_x - 1:
                line = line[:max_x - 1]
            stdscr.addstr(row, 0, line)
            row += 1

    # Highlight changes in "Raw Submessage Data"
    if "Raw Submessage Data" in parsed_data:
        raw_data_bytes = parsed_data["Raw Submessage Data"]
        previous_raw_data_bytes = previous_raw_data if previous_raw_data is not None else b""
        row += 1
        stdscr.addstr(row, 0, "Raw Submessage Data Changes:", curses.A_BOLD)
        row += 1

        for i in range(len(raw_data_bytes)):
            if i < len(previous_raw_data_bytes) and raw_data_bytes[i] == previous_raw_data_bytes[i]:
                color = curses.color_pair(0)  # Default color
            else:
                color = curses.color_pair(3)  # Yellow for changed bytes
            
            stdscr.addstr(row, (i % (max_x // 3)) * 3, f"{raw_data_bytes[i]:02x}", color)
            if (i % (max_x // 3)) == (max_x // 3) - 1:
                row += 1

        previous_raw_data = raw_data_bytes

    stdscr.refresh()

def main(stdscr):
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    stdscr.clear()
    stdscr.refresh()

    # Start packet sniffing in a non-blocking manner
    while True:
        sniff(filter="udp port 7400 or udp port 7401", prn=lambda pkt: packet_callback(pkt, stdscr), store=0, count=1)

if __name__ == "__main__":
    curses.wrapper(main)
