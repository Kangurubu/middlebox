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

# Track established connections
active_connections = {}

def decrypt_data():
    global covert_data
    try:
        f = Fernet(SYMMETRIC_KEY)
        decrypted = f.decrypt(bytes(covert_data))
        covert_data = decrypted
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
            decrypt_data()
        except Exception as e:
            print(f"Warning: Could not decrypt data: {e}")

    utc_plus_3 = timezone(timedelta(hours=3))
    timestamp = datetime.now(utc_plus_3).strftime("%d-%m_%H-%M-%S")
    json_filename = os.path.join(output_dir, f"{prefix}_{timestamp}_metadata.json")

    # Calculate statistics
    duration = (last_packet_timestamp - start_timestamp) if (start_timestamp and last_packet_timestamp) else None
    bits_received = len(covert_data) * 8
    capacity = bits_received / duration if (duration and duration > 0) else None

    metadata = {
        "timestamp": timestamp,
        "file_size_bytes": len(covert_data),
        "file_size_bits": bits_received,
        "transmission_duration": duration,
        "measured_capacity_bps": capacity,
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

def build_ip_header(src_ip, dst_ip, ip_id=0):
    """Build an IP header"""
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45,                      # Version and IHL
        0,                         # TOS
        20 + 20,                   # Total Length (IP + TCP)
        ip_id,                     # ID
        0,                         # Flags and Fragment Offset
        64,                        # TTL
        socket.IPPROTO_TCP,        # Protocol
        0,                         # Checksum (will be filled by the kernel)
        socket.inet_aton(src_ip),  # Source IP
        socket.inet_aton(dst_ip)   # Destination IP
    )
    return ip_header

def build_tcp_header(src_port, dst_port, seq, ack_seq, flags):
    """Build a TCP header"""
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port,         # Source Port
        dst_port,         # Destination Port
        seq,              # Sequence Number
        ack_seq,          # Acknowledgment Number
        5 << 4,           # Data Offset (5 words = 20 bytes)
        flags,            # Flags
        8192,             # Window Size
        0,                # Checksum (will be filled by the kernel)
        0                 # Urgent Pointer
    )
    return tcp_header

def calculate_checksum(msg):
    """Calculate the IP/TCP checksum"""
    s = 0
    # Loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        if i + 1 < len(msg):
            a = msg[i]
            b = msg[i+1]
            s = s + (a + (b << 8))
        elif i + 1 == len(msg):
            s = s + msg[i]
    
    # One's complement
    s = s + (s >> 16)
    s = ~s & 0xffff
    
    return s

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

    urg_ptr = 0
    if flags & URG:
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

def send_tcp_packet(send_socket, src_ip, dst_ip, src_port, dst_port, seq, ack_seq, flags):
    """Send a TCP packet with the given parameters"""
    # Build packet
    ip_header = build_ip_header(src_ip, dst_ip)
    tcp_header = build_tcp_header(src_port, dst_port, seq, ack_seq, flags)
    
    # Send packet
    packet = ip_header + tcp_header
    send_socket.sendto(packet, (dst_ip, 0))
    
    return True

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
        
        # Create raw socket for sending packets
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
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

        # Connection tracking key
        conn_key = f"{packet_info['src_ip']}:{packet_info['src_port']}"
        
        # Handle SYN packets (first part of TCP handshake)
        if (packet_info['flags'] & SYN) and not (packet_info['flags'] & ACK):
            print(f"Received SYN from {conn_key}")
            
            # Generate random sequence number
            our_seq = random.randint(1000, 9000)
            
            # Send SYN-ACK
            send_tcp_packet(
                send_socket, 
                os.getenv('INSECURENET_HOST_IP'), packet_info['src_ip'],
                port, packet_info['src_port'],
                our_seq, packet_info['seq'] + 1,
                SYN | ACK  # SYN-ACK flags
            )
            
            # Store connection info
            active_connections[conn_key] = {
                'their_seq': packet_info['seq'] + 1,
                'our_seq': our_seq + 1,
                'state': 'SYN_RECEIVED'
            }
            
            print(f"Sent SYN-ACK to {conn_key}")
            continue
            
        # Handle ACK packets (third part of TCP handshake)
        if (packet_info['flags'] & ACK) and conn_key in active_connections and active_connections[conn_key]['state'] == 'SYN_RECEIVED':
            print(f"Received ACK from {conn_key} - TCP handshake completed")
            active_connections[conn_key]['state'] = 'ESTABLISHED'
            continue
        
        current_time = time.time()
        if start_timestamp is None:
            start_timestamp = current_time
        last_packet_timestamp = current_time
        
        # Process URG packets for data extraction
        if packet_info['flags'] & URG and packet_info['urg_ptr'] > 0:
            urg_value = packet_info['urg_ptr'] & mask  # Apply mask to extract only the bits we want
            process_urg_value(urg_value)
            # print(f"From {packet_info['src_ip']}:{packet_info['src_port']} - URG={urg_value} (0x{urg_value:04X}) | Total: {len(covert_data)} bytes")
        
        # Check for end marker (FIN flag)
        if packet_info['flags'] & FIN:
            print(f"FIN received from {conn_key}")

            # Send ACK for FIN
            if conn_key in active_connections:
                send_tcp_packet(
                    send_socket, 
                    os.getenv('INSECURENET_HOST_IP'), packet_info['src_ip'],
                    port, packet_info['src_port'],
                    active_connections[conn_key]['our_seq'], 
                    active_connections[conn_key]['their_seq'],
                    ACK  # ACK flag
                )
                print(f"Sent ACK for FIN to {conn_key}")
                
                # Clean up connection state
                del active_connections[conn_key]

            flush_bit_buffer()

            if len(covert_data) > 0:
                if start_timestamp and last_packet_timestamp:
                    duration = last_packet_timestamp - start_timestamp
                    bits_received = len(covert_data) * 8
                    capacity = bits_received / duration if duration > 0 else 0
                    print(f"Transmission statistics:")
                    print(f"  Duration: {duration:.2f} seconds")
                    print(f"  Bytes received: {len(covert_data)}")
                    print(f"  Bits received: {bits_received}")
                    print(f"  Measured capacity: {capacity:.2f} bits/second")
                save_file()
                start_timestamp = None
            else:
                print("Warning: No data received before FIN.")

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