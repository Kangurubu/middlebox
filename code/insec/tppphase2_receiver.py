import socket
import struct
import argparse
import os
import signal
import sys
import time
from cryptography.fernet import Fernet
from datetime import datetime

# Global variables
covert_data = bytearray()
output_dir = "./received_files"
use_decryption = False
# Bit buffer globals
bit_buffer = 0
bit_count = 0

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
    """Decrypt data using the hardcoded symmetric key"""
    global covert_data
    try:
        f = Fernet(SYMMETRIC_KEY)
        decrypted  = f.decrypt(bytes(covert_data))
        covert_data = decrypted
        print(f"Decrypted data: {covert_data.decode('utf-8')}")
    except Exception as e:
        print(f"Decryption error: {e}")

def handle_exit(signum, frame):
    """Handle Ctrl+C and save any collected data"""
    print("\nReceiver shutting down...")
    sys.exit(0)

def save_file(prefix="received_file"):
    global covert_data

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Decrypt if enabled
    if use_decryption:
        try:
            print("Attempting to decrypt received data...")
            print("Data: ",covert_data)
            decrypt_data()
        except Exception as e:
            print(f"Warning: Could not decrypt data: {e}")

    # Save as text file
    txt_filename = os.path.join(output_dir, f"{prefix}_{datetime.now().strftime("%H-%M-%S")}.txt")
    try:
        with open(txt_filename, 'w', encoding='utf-8') as f:
            f.write(covert_data.decode('utf-8'))
        print(f"Text file saved: {txt_filename}")
        covert_data = bytearray()  # Clear the buffer after saving
    except Exception as e:
        print(f"Could not save as text: {e}")

    return txt_filename


def parse_ip_header(packet):
    """Parse the IP header"""
    # IP header: first 20 bytes of the packet
    ip_header = packet[0:20]
    # Unpack the header
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    
    ip_header_length = ihl * 4
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    
    return {
        'length': ip_header_length,
        'protocol': protocol,
        'src_addr': s_addr,
        'dst_addr': d_addr
    }

def parse_tcp_header(packet, ip_header_length):
    """Parse the TCP header"""
    tcp_header = packet[ip_header_length:ip_header_length + 20]
    
    # Unpack the TCP header
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    
    flags = tcph[5]
    window = tcph[6]
    checksum = tcph[7]
    urgent_pointer = tcph[8]
    
    return {
        'src_port': source_port,
        'dst_port': dest_port,
        'seq': sequence,
        'ack': acknowledgement,
        'length': tcph_length * 4,
        'flags': flags,
        'window': window,
        'checksum': checksum,
        'urg_ptr': urgent_pointer
    }

def handle_syn(packet, ip_header, tcp_header):
    """Handle SYN packet and respond with SYN-ACK"""
    try:
        # Create response socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Craft SYN-ACK packet
        source_ip = ip_header['dst_addr']
        dest_ip = ip_header['src_addr']
        
        # IP header
        ip_ver = 4
        ip_ihl = 5
        ip_tos = 0
        ip_tot_len = 40  # IP header + TCP header
        ip_id = os.getpid() & 0xFFFF
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0  # Will be calculated by the kernel
        
        ip_saddr = socket.inet_aton(source_ip)
        ip_daddr = socket.inet_aton(dest_ip)
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ihl_ver,
            ip_tos,
            ip_tot_len,
            ip_id,
            ip_frag_off,
            ip_ttl,
            ip_proto,
            ip_check,
            ip_saddr,
            ip_daddr
        )
        
        # TCP header
        tcp_source = tcp_header['dst_port']
        tcp_dest = tcp_header['src_port']
        tcp_seq = int(time.time())
        tcp_ack_seq = tcp_header['seq'] + 1
        tcp_doff = 5  # TCP header size in 32-bit words
        tcp_fin = 0
        tcp_syn = 1
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 1
        tcp_urg = 0
        tcp_window = socket.htons(5840)
        tcp_check = 0  # Will be calculated later
        tcp_urg_ptr = 0
        
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
        
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_source,
            tcp_dest,
            tcp_seq,
            tcp_ack_seq,
            tcp_offset_res,
            tcp_flags,
            tcp_window,
            tcp_check,
            tcp_urg_ptr
        )
        
        # Pseudo header for checksum calculation
        source_address = socket.inet_aton(source_ip)
        dest_address = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        
        psh = struct.pack('!4s4sBBH',
            source_address,
            dest_address,
            placeholder,
            protocol,
            tcp_length
        )
        
        psh = psh + tcp_header
        tcp_check = checksum(psh)
        
        # Pack the TCP header again with the correct checksum
        tcp_header = struct.pack('!HHLLBBH',
            tcp_source,
            tcp_dest,
            tcp_seq,
            tcp_ack_seq,
            tcp_offset_res,
            tcp_flags,
            tcp_window
        ) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
        
        # Final packet
        packet = ip_header + tcp_header
        
        # Send SYN-ACK packet
        s.sendto(packet, (dest_ip, 0))
        
        print(f"Sent SYN-ACK to {dest_ip}:{tcp_dest}")
        
        # Don't wait for ACK as we're passive and will process future packets in the main loop
        
        return tcp_seq, tcp_ack_seq
    except socket.error as e:
        print(f"Failed to send SYN-ACK: {e}")
        return None, None
    finally:
        s.close()

def checksum(msg):
    """Calculate the checksum of a message"""
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
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    
    # Complement and convert to integer
    result = ~s & 0xffff
    
    return result

def append_bits(value, bits, conn_id):
    global bit_buffer, bit_count, covert_data
    bit_buffer = (bit_buffer << bits) | value
    bit_count += bits
    
    while bit_count >= 8:
        bit_count -= 8
        byte = (bit_buffer >> bit_count) & 0xFF
        covert_data += bytes([byte])

def start_receiver(bits_to_use):    
    port = 8888
    # Create a raw socket
    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as e:
        print(f"Socket creation error: {e}")
        sys.exit(1)
    
    # Setup signal handler for graceful exit
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
        
        ip_header = parse_ip_header(packet)
        
        # Skip non-TCP packets
        if ip_header['protocol'] != socket.IPPROTO_TCP:
            continue
        
        tcp_header = parse_tcp_header(packet, ip_header['length'])
        
        # Only process packets destined for our port
        if tcp_header['dst_port'] != port:
            continue
        
        conn_id = (ip_header['src_addr'], tcp_header['src_port'])
        
        # TCP handshake
        # SYN packet received
        if tcp_header['flags'] & SYN and not (tcp_header['flags'] & ACK):
            print(f"Received SYN from {conn_id[0]}:{conn_id[1]}")
            seq, ack = handle_syn(packet, ip_header, tcp_header)
        
        # Process URG packets for data extraction
        if tcp_header['flags'] & URG and tcp_header['urg_ptr'] > 0:
            urg_value = tcp_header['urg_ptr'] & mask  # Apply mask to extract only the bits we want
            append_bits(urg_value, bits_to_use, conn_id) # Bit-level accumulation
            print(f"From {conn_id[0]}:{conn_id[1]} - URG={urg_value} (0x{urg_value:0{4 if bits_to_use > 8 else 2}X}) | Total: {len(covert_data)} bytes")
        
        # Check for end marker (FIN flag)
        if tcp_header['flags'] & FIN and tcp_header['flags'] & ACK:
            print(f"End of transmission detected from {conn_id[0]}:{conn_id[1]}")
            save_file()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert channel receiver using TCP URG pointer")
    parser.add_argument('--output', default='./received_files', help="Output directory for received files")
    parser.add_argument('--bits', type=int, default=16, help="Number of bits to use from the urgent pointer (1-16)")
    parser.add_argument('--decrypt', action='store_true', help="Enable decryption of received data")
    args = parser.parse_args()

    # Update global variables from command line arguments
    output_dir = args.output
    bits_to_use = max(1, min(16, args.bits))  # Ensure bits_to_use is between 1 and 16
    use_decryption = args.decrypt
    
    start_receiver(bits_to_use)