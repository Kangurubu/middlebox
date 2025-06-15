#!/usr/bin/env python3

import socket
import threading
from datetime import datetime

class TrafficReceiver:
    def __init__(self, port=8888):
        self.port = port
        self.running = False
        self.stats = {
            'udp_packets_received': 0,
            'tcp_connections': 0,
            'bytes_received': 0,
            'start_time': None
        }

    def start_udp_server(self):
        """Start UDP server to receive traffic"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', self.port))
            
            print(f"UDP server listening on 0.0.0.0:{self.port}")
            
            while self.running:
                try:
                    data, addr = sock.recvfrom(4096)
                    self.stats['udp_packets_received'] += 1
                    self.stats['bytes_received'] += len(data)
                    
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                    print(f"[{timestamp}] UDP from {addr}: {data.decode()[:50]}...")
                    
                    # Send response back
                    response = f"INSEC response to packet #{self.stats['udp_packets_received']}"
                    sock.sendto(response.encode(), addr)
                    
                except Exception as e:
                    if self.running:
                        print(f"UDP receive error: {e}")
                        
        except Exception as e:
            print(f"UDP server error: {e}")
        finally:
            sock.close()

    def handle_tcp_client(self, client_socket, addr):
        """Handle TCP client connection"""
        try:
            self.stats['tcp_connections'] += 1
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            print(f"[{timestamp}] TCP connection from {addr}")
            
            data = client_socket.recv(4096)
            if data:
                self.stats['bytes_received'] += len(data)
                print(f"TCP from {addr}: {data.decode()[:50]}...")
                
                # Send response back
                response = f"INSEC TCP response to connection #{self.stats['tcp_connections']}"
                client_socket.send(response.encode())
                
        except Exception as e:
            print(f"TCP client error: {e}")
        finally:
            client_socket.close()

    def start_tcp_server(self):
        """Start TCP server to receive traffic"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)  # Add timeout for accept() to allow clean shutdown
            sock.bind(('0.0.0.0', self.port))  # Bind to all interfaces
            sock.listen(5)
            
            print(f"TCP server listening on 0.0.0.0:{self.port}")
            
            while self.running:
                try:
                    client_socket, addr = sock.accept()
                    print(f"TCP connection accepted from {addr}")
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_tcp_client, 
                        args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.timeout:
                    # Timeout is expected for clean shutdown
                    continue
                except Exception as e:
                    if self.running:
                        print(f"TCP accept error: {e}")
                        
        except Exception as e:
            print(f"TCP server error: {e}")
        finally:
            sock.close()

    def start(self, protocol='both'):
        """Start traffic receiver"""
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        print(f"INSEC Traffic Receiver starting on port {self.port}")
        print(f"Protocol: {protocol.upper()}")
        print("-" * 50)
        
        threads = []
        
        if protocol.lower() in ['udp', 'both']:
            udp_thread = threading.Thread(target=self.start_udp_server)
            udp_thread.daemon = True
            udp_thread.start()
            threads.append(udp_thread)
        
        if protocol.lower() in ['tcp', 'both']:
            tcp_thread = threading.Thread(target=self.start_tcp_server)
            tcp_thread.daemon = True
            tcp_thread.start()
            threads.append(tcp_thread)
        
        try:
            # Keep main thread alive
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            print("\nStopping traffic receiver...")
            self.stop()

    def stop(self):
        """Stop traffic receiver"""
        self.running = False

    def print_stats(self):
        """Print traffic statistics"""
        if self.stats['start_time']:
            duration = (datetime.now() - self.stats['start_time']).total_seconds()
            print(f"\n--- Traffic Receiver Statistics ---")
            print(f"Duration: {duration:.2f} seconds")
            print(f"UDP packets received: {self.stats['udp_packets_received']}")
            print(f"TCP connections: {self.stats['tcp_connections']}")
            print(f"Total bytes received: {self.stats['bytes_received']}")
            if duration > 0:
                print(f"Packets/sec: {(self.stats['udp_packets_received'] + self.stats['tcp_connections'])/duration:.2f}")

def main():
    # Default settings
    port = 8888
    protocol = 'both'
    
    # Create traffic receiver
    receiver = TrafficReceiver(port=port)
    
    try:
        # Start traffic receiver
        receiver.start(protocol)
        
    except KeyboardInterrupt:
        print("\nStopping traffic receiver...")
        receiver.stop()
    
    finally:
        receiver.print_stats()

if __name__ == "__main__":
    main()