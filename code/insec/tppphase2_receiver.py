import socket
import struct
import argparse
import os
import signal
import sys
import time
from cryptography.fernet import Fernet
import json
from datetime import datetime, timedelta, timezone
import random

# Global variables
bits_to_use = 16
covert_data = bytearray()
output_dir = "./received_files"
use_decryption = False
# Bit buffer globals
bit_buffer = 0
bit_count = 0

start_timestamp = None
last_packet_timestamp = None

# Hardcoded symmetric key - must be the same in both sender and receiver
SYMMETRIC_KEY = b'dBbg_kQbMCvR3S1tzx6yTDJL3XaG6qyTjvBEx-0vvUY='

# TCP Flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20

def decrypt_data():
    global covert_data
    try:
        print(f"Attempting to decrypt {len(covert_data)} bytes")
        print(f"Raw encrypted data (first 50 bytes): {covert_data[:50].hex()}")
        print(f"Data as string: {covert_data[:50]}")
        
        # Check if it looks like base64 Fernet token
        try:
            data_str = covert_data.decode('utf-8')
            print(f"Decoding as UTF-8 successful: {data_str[:50]}...")
        except:
            print("Data is not valid UTF-8")
        
        f = Fernet(SYMMETRIC_KEY)
        decrypted = f.decrypt(bytes(covert_data))
        covert_data = decrypted
        print(f"Successfully decrypted to {len(covert_data)} bytes")
        print(f"Decrypted data: {covert_data.decode('utf-8')}")
    except Exception as e:
        print(f"Decryption error: {e}")

def handle_exit(signum, frame):
    print("\nReceiver shutting down...")
    if len(covert_data) > 0:
        save_file()
    sys.exit(0)

def save_file(prefix="received_file"):
    global covert_data, start_timestamp, last_packet_timestamp

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Decrypt if enabled
    if use_decryption:
        try:
            print("Attempting to decrypt received data...")
            # Save original data in case decryption fails
            original_data = covert_data.copy()
            decrypt_data()
        except Exception as e:
            print(f"Warning: Could not decrypt data: {e}")
            print(f"Saving raw encrypted data for analysis")
            # Restore original encrypted data for saving
            covert_data = original_data

    utc_plus_3 = timezone(timedelta(hours=3))
    timestamp = datetime.now(utc_plus_3).strftime("%d-%m_%H-%M-%S")
    json_filename = os.path.join(output_dir, f"{prefix}_{timestamp}_metadata.json")

    # Calculate statistics - both original file size and actual received size
    duration = (last_packet_timestamp - start_timestamp) if (start_timestamp and last_packet_timestamp) else None
    original_file_bits = 800  # Always calculate based on 100-character file
    actual_received_bits = len(covert_data) * 8  # Actual data received (may be larger due to encryption)
    effective_capacity = original_file_bits / duration if (duration and duration > 0) else None
    actual_throughput = actual_received_bits / duration if (duration and duration > 0) else None

    metadata = {
        "timestamp": timestamp,
        "file_size_bytes": len(covert_data),
        "file_size_bits": original_file_bits,
        "actual_received_bits": actual_received_bits,
        "transmission_duration": duration,
        "measured_capacity_bps": effective_capacity,
        "actual_throughput_bps": actual_throughput,
        "decryption_used": use_decryption,
        "bits_to_use": bits_to_use,
    }

    with open(json_filename, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    # Save as text file
    txt_filename = os.path.join(output_dir, f"{prefix}_{timestamp}.txt")
    try:
        # Try to save as UTF-8 text
        with open(txt_filename, 'w', encoding='utf-8') as f:
            f.write(covert_data.decode('utf-8'))
        print(f"Text file saved: {txt_filename}")
    except UnicodeDecodeError:
        # If it fails, save as binary
        bin_filename = os.path.join(output_dir, f"{prefix}_{timestamp}.bin")
        with open(bin_filename, 'wb') as f:
            f.write(covert_data)
        print(f"Binary file saved: {bin_filename}")
        txt_filename = bin_filename
    
    print(f"Metadata saved: {json_filename}")
    
    # Clear the buffer after saving
    covert_data = bytearray()
    return txt_filename




def parse_packet(packet):
    """Parse a raw packet to extract TCP/IP header fields"""
    iph_length = (packet[0] & 0xF) * 4
    src_ip = socket.inet_ntoa(packet[12:16])
    dst_ip = socket.inet_ntoa(packet[16:20])
    
    tcp_header = packet[iph_length:iph_length+20]
    src_port = struct.unpack('!H', tcp_header[0:2])[0]
    dst_port = struct.unpack('!H', tcp_header[2:4])[0]
    seq = struct.unpack('!L', tcp_header[4:8])[0]
    ack_seq = struct.unpack('!L', tcp_header[8:12])[0]
    flags = tcp_header[13]    

    # Always read the urgent pointer field, regardless of URG flag
    # This follows Hintz's covert channel technique
    urg_ptr = struct.unpack('!H', tcp_header[18:20])[0]
    
    return {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'seq': seq,
        'ack_seq': ack_seq,
        'flags': flags,
        'urg_ptr': urg_ptr
    }


def is_valid_character(byte_value):
    # Check if the value is a printable ASCII character or common control character
    return (32 <= byte_value <= 126) or byte_value in [9, 10, 13]  # Include tab, newline, carriage return

def process_urg_value(value):
    global bit_buffer, bit_count, covert_data

    # Mask to ensure only 'bits_to_use' bits are taken
    value &= (1 << bits_to_use) - 1

    # If we're using 16 bits but transmitting 8-bit characters,
    # check if the value is within valid ASCII range
    if bits_to_use == 16 and value <= 0xFF and is_valid_character(value):
        # Direct byte mode - if urgent pointer contains a valid character
        covert_data.append(value)
        print(f"Added direct valid character: {chr(value) if is_valid_character(value) else hex(value)}")
        return

    # For other cases, use the bit buffer approach
    bit_buffer = (bit_buffer << bits_to_use) | value
    bit_count += bits_to_use

    while bit_count >= 8:
        bit_count -= 8
        byte = (bit_buffer >> bit_count) & 0xFF
        # Only add the byte if it's a valid character or we're in binary mode
        if is_valid_character(byte) or not all(is_valid_character(b) for b in covert_data):
            covert_data.append(byte)
            # print(f"Added buffered byte: {chr(byte) if is_valid_character(byte) else hex(byte)}")

def flush_bit_buffer():
    global bit_buffer, bit_count, covert_data
    
    # Only flush the bit buffer if it contains a reasonable amount of bits
    # and likely represents actual data (at least 4 bits)
    if bit_count >= 4:
        # Determine if we should pad or discard based on context
        if all(is_valid_character(b) for b in covert_data):
            # If all previous bytes are valid characters, only add this byte
            # if it would result in a valid character
            byte = (bit_buffer << (8 - bit_count)) & 0xFF
            if is_valid_character(byte):
                covert_data.append(byte)
                print(f"Flushed partial byte (completed): {chr(byte)}")
        else:
            # If we're in binary mode, just append the partial byte
            byte = (bit_buffer << (8 - bit_count)) & 0xFF
            covert_data.append(byte)
            print(f"Flushed partial byte: {hex(byte)}")
    
    # Reset bit buffer regardless
    bit_buffer = 0
    bit_count = 0

def start_receiver(port=8888):
    global start_timestamp, last_packet_timestamp
    start_timestamp = None
    last_packet_timestamp = None
    
    try:
        # Create raw socket for receiving packets
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as e:
        print(f"Socket creation error: {e}")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    
    # Prepare mask based on bits_to_use
    mask = (1 << bits_to_use) - 1
    
    print(f"Listening for covert data on TCP port {port}...")
    print(f"Using {bits_to_use} bits of the urgent pointer field (mask: 0x{mask:04X})")
    print(f"Decryption {'enabled' if use_decryption else 'disabled'}")
    print(f"Received files will be saved to {output_dir}")

    while True:
        packet, addr = recv_socket.recvfrom(65565)
        
        if packet[9] != socket.IPPROTO_TCP:
            continue
        
        packet_info = parse_packet(packet)
        
        if packet_info['dst_port'] != port:
            continue

        current_time = time.time()
        if start_timestamp is None:
            start_timestamp = current_time
        last_packet_timestamp = current_time
        
        # Check for finish signal first
        if packet_info['urg_ptr'] == 0xDEAD:
            print(f"Finish signal received from {packet_info['src_ip']}:{packet_info['src_port']} - URG=0xDEAD")
            flush_bit_buffer()

            if len(covert_data) > 0:
                if start_timestamp and last_packet_timestamp:
                    duration = last_packet_timestamp - start_timestamp
                    original_file_bits = 800  # Always calculate based on 100-character file
                    actual_received_bits = len(covert_data) * 8
                    effective_capacity = original_file_bits / duration if duration > 0 else 0
                    actual_throughput = actual_received_bits / duration if duration > 0 else 0
                    print(f"Transmission statistics:")
                    print(f"  Duration: {duration:.2f} seconds")
                    print(f"  Bytes received: {len(covert_data)}")
                    print(f"  Original file bits: {original_file_bits}")
                    print(f"  Actual received bits: {actual_received_bits}")
                    print(f"  Effective capacity (original): {effective_capacity:.2f} bits/second")
                    print(f"  Actual throughput (received): {actual_throughput:.2f} bits/second")
                save_file()
                start_timestamp = None
            else:
                print("Warning: No data received before finish signal.")
            
            print("Transmission complete - shutting down receiver...")
            sys.exit(0)
        
        # Process packets with URG pointer data
        if packet_info['urg_ptr'] > 0 and packet_info['urg_ptr'] != 0xDEAD:
            urg_value = packet_info['urg_ptr'] & mask  # Apply mask to extract only the bits we want
            process_urg_value(urg_value)
            # print(f"From {packet_info['src_ip']}:{packet_info['src_port']} - URG={urg_value} (0x{urg_value:04X}) | Total: {len(covert_data)} bytes")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert channel receiver using TCP URG pointer")
    parser.add_argument('--port', type=int, default=8888, help="Port to listen on")
    parser.add_argument('--output', default='./received_files', help="Output directory for received files")
    parser.add_argument('--bits', type=int, default=16, help="Number of bits to use from the urgent pointer (1-16)")
    parser.add_argument('--decrypt', action='store_true', help="Enable decryption of received data")
    args = parser.parse_args()

    output_dir = args.output
    bits_to_use = max(1, min(16, args.bits))
    use_decryption = args.decrypt
    
    start_receiver(args.port)