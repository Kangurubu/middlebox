#!/usr/bin/env python3

import socket
import time
import threading
import random
import string
import os
import sys
from datetime import datetime

class TrafficGenerator:
    def __init__(self, target_ip, target_port=8888, source_port=8888, interval=1.0, packet_size=64):
        self.target_ip = target_ip
        self.target_port = target_port
        self.source_port = source_port
        self.interval = interval
        self.packet_size = packet_size
        self.running = False
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'start_time': None
        }

    def generate_payload(self, size):
        """Generate random payload of specified size"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=size))

    def send_udp_traffic(self):
        """Send UDP traffic to target"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)  # 2 second timeout
            
            print(f"Starting UDP traffic generation to {self.target_ip}:{self.target_port}")
            print(f"Packet size: {self.packet_size} bytes, Interval: {self.interval}s")
            
            while self.running:
                try:
                    # Generate payload
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                    payload = f"[{timestamp}] {self.generate_payload(self.packet_size - 50)}"
                    
                    # Send packet
                    sock.sendto(payload.encode(), (self.target_ip, self.target_port))
                    self.stats['packets_sent'] += 1
                    self.stats['bytes_sent'] += len(payload)
                    
                    print(f"Sent packet #{self.stats['packets_sent']} to {self.target_ip}:{self.target_port}")
                    
                    # Try to receive response
                    try:
                        response, addr = sock.recvfrom(4096)
                        self.stats['packets_received'] += 1
                        self.stats['bytes_received'] += len(response)
                        print(f"Received response from {addr}: {response.decode()[:50]}...")
                    except socket.timeout:
                        print("No response received (timeout)")
                    
                    time.sleep(self.interval)
                    
                except Exception as e:
                    print(f"Error sending packet: {e}")
                    time.sleep(self.interval)
                    
        except Exception as e:
            print(f"UDP socket error: {e}")
        finally:
            sock.close()

    def send_tcp_traffic(self):
        """Send TCP traffic to target"""
        print(f"Starting TCP traffic generation to {self.target_ip}:{self.target_port}")
        
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                
                # Connect to target
                sock.connect((self.target_ip, self.target_port))
                
                # Generate and send payload
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                payload = f"[{timestamp}] {self.generate_payload(self.packet_size - 50)}"
                
                sock.send(payload.encode())
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(payload)
                
                print(f"Sent TCP packet #{self.stats['packets_sent']} to {self.target_ip}:{self.target_port}")
                
                # Try to receive response
                try:
                    response = sock.recv(4096)
                    self.stats['packets_received'] += 1
                    self.stats['bytes_received'] += len(response)
                    print(f"Received TCP response: {response.decode()[:50]}...")
                except socket.timeout:
                    print("No TCP response received (timeout)")
                
                sock.close()
                time.sleep(self.interval)
                
            except Exception as e:
                print(f"TCP connection error: {e}")
                time.sleep(self.interval)

    def send_icmp_traffic(self):
        """Send ICMP ping traffic to target"""
        print(f"Starting ICMP traffic generation to {self.target_ip}")
        
        while self.running:
            try:
                # Use system ping command
                result = os.system(f"ping -c 1 -W 2 {self.target_ip} > /dev/null 2>&1")
                
                self.stats['packets_sent'] += 1
                
                if result == 0:
                    self.stats['packets_received'] += 1
                    print(f"ICMP ping #{self.stats['packets_sent']} to {self.target_ip}: SUCCESS")
                else:
                    print(f"ICMP ping #{self.stats['packets_sent']} to {self.target_ip}: FAILED")
                
                time.sleep(self.interval)
                
            except Exception as e:
                print(f"ICMP ping error: {e}")
                time.sleep(self.interval)

    def start(self, protocol='udp'):
        """Start traffic generation"""
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        if protocol.lower() == 'udp':
            self.send_udp_traffic()
        elif protocol.lower() == 'tcp':
            self.send_tcp_traffic()
        elif protocol.lower() == 'icmp':
            self.send_icmp_traffic()
        else:
            print(f"Unsupported protocol: {protocol}")

    def stop(self):
        """Stop traffic generation"""
        self.running = False

    def print_stats(self):
        """Print traffic statistics"""
        if self.stats['start_time']:
            duration = (datetime.now() - self.stats['start_time']).total_seconds()
            print(f"\n--- Traffic Generation Statistics ---")
            print(f"Duration: {duration:.2f} seconds")
            print(f"Packets sent: {self.stats['packets_sent']}")
            print(f"Packets received: {self.stats['packets_received']}")
            print(f"Bytes sent: {self.stats['bytes_sent']}")
            print(f"Bytes received: {self.stats['bytes_received']}")
            print(f"Packets/sec: {self.stats['packets_sent']/duration:.2f}")
            print(f"Success rate: {(self.stats['packets_received']/max(1,self.stats['packets_sent']))*100:.1f}%")

def main():
    # Default settings
    target_ip = os.getenv('INSECURENET_HOST_IP', '10.0.0.21')
    target_port = 8888
    protocol = 'tcp'
    interval = 1.0
    packet_size = 256
    
    print(f"SEC Traffic Generator")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Protocol: {protocol.upper()}")
    print(f"Interval: {interval}s")
    print(f"Packet size: {packet_size} bytes")
    print(f"Duration: infinite")
    print("-" * 50)
    
    # Create traffic generator
    generator = TrafficGenerator(
        target_ip=target_ip,
        target_port=target_port,
        interval=interval,
        packet_size=packet_size
    )
    
    try:
        # Start traffic generation
        generator.start(protocol)
        
    except KeyboardInterrupt:
        print("\nStopping traffic generation...")
        generator.stop()
    
    finally:
        generator.print_stats()

if __name__ == "__main__":
    main()