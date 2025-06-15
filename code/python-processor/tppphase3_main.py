#!/usr/bin/env python3
"""
Covert Channel Detector - Monitors real NATS traffic for covert channels
Runs in the middlebox while actual TPPhase2 sender/receiver are active
"""

import asyncio
import json
import os
import time
import statistics
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import numpy as np
from nats.aio.client import Client as NATS
from helper.covert_channel_detector import CovertChannelDetector
from scapy.all import Ether, IP, TCP

# This function will update the TCP checksum for the packet
# Without this, TCP doesn't work
def update_tcp_checksum(packet):
    if TCP in packet:
        del packet[TCP].chksum  # Delete the checksum field
        packet[TCP].chksum = None  # Set it to None, forcing Scapy to recompute it
    return packet

class NATSDetector:
    """Detector that monitors NATS traffic"""
    
    def __init__(self, 
                 threshold: float = 0.5,
                 entropy_threshold: float = 0.3,
                 monitoring_duration: int = 300):  # 5 minutes default
        
        self.detector = CovertChannelDetector(
            anomaly_threshold=threshold,
            urg_entropy_threshold=entropy_threshold
        )
        
        self.nc = None
        self.monitoring_duration = monitoring_duration
        self.captured_packets = []
        self.is_monitoring = False
        self.start_time = None
        self.detection_log = []
        self.monitoring_task = None
        
        # Track packet patterns for covert channel identification
        self.urg_packets = 0
        self.total_packets = 0
        
    async def connect_nats(self):
        """Connect to NATS server"""
        self.nc = NATS()
        nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
        await self.nc.connect(nats_url)
        print(f"Connected to NATS server: {nats_url}")
        
    async def packet_handler(self, msg):
        """Handle packets from NATS and perform detection"""
        try:
            if not self.is_monitoring:
                # Forward packet even if not monitoring
                out_topic = "outpktinsec" if msg.subject == "inpktsec" else "outpktsec"
                # Update TCP checksum before forwarding
                try:
                    packet = Ether(msg.data)
                    packet = update_tcp_checksum(packet)
                    await self.nc.publish(out_topic, bytes(packet))
                except:
                    # If packet parsing fails, forward original data
                    await self.nc.publish(out_topic, msg.data)
                return
                
            subject = msg.subject
            data = msg.data
            timestamp = time.time()
            
            self.total_packets += 1
            
            # Analyze packet structure
            packet_info = self.analyze_packet_structure(data)
            
            # Determine if this packet is likely covert based on patterns
            is_likely_covert = self.classify_packet(packet_info, timestamp)
            
            # Store packet for analysis
            self.captured_packets.append({
                'data': data,
                'timestamp': timestamp,
                'subject': subject,
                'packet_info': packet_info,
                'is_likely_covert': is_likely_covert
            })
            
            # Run detection
            analysis = self.detector.analyze_packet(data, timestamp, is_likely_covert)
            
            # Store detection results if anomaly detected
            if analysis and analysis.is_anomalous:
                self.detection_log.append({
                    'timestamp': timestamp,
                    'confidence': analysis.confidence,
                    'anomaly_reasons': analysis.anomaly_reasons,
                    'packet_info': packet_info,
                    'is_likely_covert': is_likely_covert
                })
            
            # Print one-line status for each packet
            covert_status = "COVERT" if is_likely_covert else "LEGIT"
            detection_status = ""
            if analysis and analysis.is_anomalous:
                detection_status = f" | DETECTED (conf: {analysis.confidence:.2f})"
            
            if packet_info:
                # Map IP addresses to container names
                src_name = "sec" if packet_info['src_ip'].endswith('.2') else "insec"
                dst_name = "insec" if packet_info['dst_ip'].endswith('.3') else "sec"
                
                # print(f"[{covert_status}]{detection_status} | "
                #       f"{src_name}:{packet_info['src_port']} -> "
                #       f"{dst_name}:{packet_info['dst_port']} | "
                #       f"URG={packet_info['urg_pointer']} | "
                #       f"Flags={packet_info['flags']}")
                
                # Check for covert channel finish signal packet
                if (packet_info['dst_port'] == 8888 and 
                    packet_info['urg_pointer'] == 0xDEAD and
                    'P' in packet_info['flags']):
                    
                    # Check payload for finish message
                    try:
                        packet = Ether(data)
                        if TCP in packet and packet[TCP].payload:
                            payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
                            if "COVERT_CHANNEL_FINISHED" in payload:
                                print(f"\n[INFO] Covert channel finish signal detected!")
                                print("Forwarding finish packet and stopping monitoring...")
                                
                                # Forward the finish packet first
                                out_topic = "outpktinsec" if subject == "inpktsec" else "outpktsec"
                                try:
                                    packet = update_tcp_checksum(packet)
                                    await self.nc.publish(out_topic, bytes(packet))
                                except:
                                    await self.nc.publish(out_topic, data)
                                
                                # Stop monitoring after brief delay
                                if self.monitoring_task:
                                    await asyncio.sleep(1)
                                    self.monitoring_task.cancel()
                                return
                    except:
                        pass
            
            
            # Forward packet (maintain transparency)
            out_topic = "outpktinsec" if subject == "inpktsec" else "outpktsec"
            
            # Update TCP checksum before forwarding
            try:
                packet = Ether(data)
                packet = update_tcp_checksum(packet)
                await self.nc.publish(out_topic, bytes(packet))
            except:
                # If packet parsing fails, forward original data
                await self.nc.publish(out_topic, data)
            
        except Exception as e:
            print(f"Error in packet handler: {e}")
            # Still forward the packet
            try:
                out_topic = "outpktinsec" if msg.subject == "inpktsec" else "outpktsec"
                # Try to update TCP checksum even in error case
                try:
                    packet = Ether(msg.data)
                    packet = update_tcp_checksum(packet)
                    await self.nc.publish(out_topic, bytes(packet))
                except:
                    await self.nc.publish(out_topic, msg.data)
            except:
                pass
    
    def analyze_packet_structure(self, packet_data: bytes) -> Optional[Dict]:
        """Analyze packet structure and extract relevant information"""
        try:
            packet = Ether(packet_data)
            if not (IP in packet and TCP in packet):
                return None
            
            tcp_layer = packet[TCP]
            ip_layer = packet[IP]
            
            info = {
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'has_urg_flag': bool(tcp_layer.flags & 0x20),
                'urg_pointer': tcp_layer.urgptr,
                'payload_length': len(tcp_layer.payload) if tcp_layer.payload else 0,
                'flags': tcp_layer.sprintf("%TCP.flags%")
            }
            
            return info
            
        except Exception as e:
            return None
    
    def classify_packet(self, packet_info: Optional[Dict], timestamp: float) -> bool:
        """Classify if packet is likely covert based on patterns"""
        if not packet_info:
            return False
        
        # Count packets with URG pointer activity (with or without URG flag)
        if packet_info['has_urg_flag'] or packet_info['urg_pointer'] > 0:
            self.urg_packets += 1
        
        # Heuristics for covert channel classification
        is_covert = False
        
        # Only check for URG-based covert channels, not port-based
        # Pattern 1: URG flag with specific patterns that suggest covert data
        if packet_info['has_urg_flag'] and packet_info['urg_pointer'] > 0:
            # URG pointer in ASCII range suggests data encoding
            if 32 <= packet_info['urg_pointer'] <= 126:
                is_covert = True
            # URG pointer with minimal payload
            elif packet_info['payload_length'] <= 1:
                is_covert = True
        
        # Pattern 2: URG pointer without URG flag (protocol violation)
        if not packet_info['has_urg_flag'] and packet_info['urg_pointer'] > 0:
            is_covert = True
        
        return is_covert
    
    async def start_monitoring(self):
        """Start monitoring NATS traffic"""
        await self.connect_nats()
        
        # Subscribe to packet topics
        await self.nc.subscribe("inpktsec", cb=self.packet_handler)
        await self.nc.subscribe("inpktinsec", cb=self.packet_handler)
        
        self.is_monitoring = True
        self.start_time = time.time()
        print(f"Started monitoring NATS traffic for {self.monitoring_duration} seconds")
        print("Detector is running in transparent mode - all packets are forwarded")
        print("Detection alerts will be logged when anomalies are found")
        print("-" * 60)
        
        # Monitor for specified duration
        try:
            self.monitoring_task = asyncio.create_task(asyncio.sleep(self.monitoring_duration))
            await self.monitoring_task
        except asyncio.CancelledError:
            print("Monitoring cancelled - user interrupted")
        
        await self.stop_monitoring()
    
    async def stop_monitoring(self):
        """Stop monitoring and generate report"""
        self.is_monitoring = False
        
        if self.nc:
            await self.nc.close()
        
        print("\n" + "="*60)
        print("Monitoring completed. Generating detection report...")
        self.generate_detection_report()
    
    def generate_detection_report(self):
        """Generate report from monitoring session"""
        
        if not self.captured_packets:
            print("No packets captured during monitoring session.")
            return
        
        # Get detection metrics
        metrics = self.detector.get_detection_metrics()
        summary = self.detector.get_summary_stats()
        
        # Calculate session statistics
        monitoring_time = time.time() - self.start_time if self.start_time else 0
        packets_per_second = len(self.captured_packets) / monitoring_time if monitoring_time > 0 else 0
        
        # Classification statistics
        covert_packets = sum(1 for p in self.captured_packets if p['is_likely_covert'])
        legitimate_packets = len(self.captured_packets) - covert_packets
        
        print("\nMONITORING SESSION REPORT")
        print("=" * 50)
        print(f"Monitoring Duration: {monitoring_time:.1f} seconds")
        print(f"Total Packets Processed: {len(self.captured_packets)}")
        print(f"Packets per Second: {packets_per_second:.1f}")
        print(f"URG Flag Packets: {self.urg_packets}")
        print()
        
        print("PACKET CLASSIFICATION:")
        print(f"Likely Covert Packets: {covert_packets}")
        print(f"Likely Legitimate Packets: {legitimate_packets}")
        print(f"Covert Traffic Ratio: {covert_packets/len(self.captured_packets):.3f}")
        print()
        
        print("DETECTION PERFORMANCE:")
        if metrics:
            print(f"F1-Score: {metrics.get('f1_score', 0):.3f}")
            print(f"Accuracy: {metrics.get('accuracy', 0):.3f}")
            print(f"Precision: {metrics.get('precision', 0):.3f}")
            print(f"Recall: {metrics.get('recall', 0):.3f}")
            print(f"False Positive Rate: {metrics.get('fpr', 0):.3f}")
            print()
            
            print("CONFUSION MATRIX:")
            print(f"True Positives: {metrics.get('tp', 0)}")
            print(f"True Negatives: {metrics.get('tn', 0)}")
            print(f"False Positives: {metrics.get('fp', 0)}")
            print(f"False Negatives: {metrics.get('fn', 0)}")
        print()
        
        print("DETECTION ALERTS:")
        print(f"Total Anomalies Detected: {len(self.detection_log)}")
        
        # Show high-confidence detections
        high_conf_detections = [d for d in self.detection_log if d['confidence'] > 0.7]
        print(f"High Confidence Detections: {len(high_conf_detections)}")
        
        if high_conf_detections:
            print("\nTop Detection Events:")
            for i, detection in enumerate(sorted(high_conf_detections, 
                                               key=lambda x: x['confidence'], 
                                               reverse=True)[:5]):
                print(f"  {i+1}. Confidence: {detection['confidence']:.3f}")
                print(f"     Reasons: {', '.join(detection['anomaly_reasons'])}")
                if detection['packet_info']:
                    pi = detection['packet_info']
                    print(f"     {pi['src_ip']}:{pi['src_port']} -> {pi['dst_ip']}:{pi['dst_port']}")
                    print(f"     URG: {pi['has_urg_flag']}, URG Pointer: {pi['urg_pointer']}")
                print()
        
        # Save detailed results
        self.save_session_results(metrics, summary, monitoring_time)
    
    def save_session_results(self, metrics: Dict, summary: Dict, monitoring_time: float):
        """Save session results to file"""
        
        os.makedirs("benchmark_results", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Prepare results data
        results = {
            'session_info': {
                'timestamp': timestamp,
                'monitoring_duration': monitoring_time,
                'detector_threshold': self.detector.anomaly_threshold,
                'detector_entropy_threshold': self.detector.urg_entropy_threshold,
                'total_packets': len(self.captured_packets),
                'urg_packets': self.urg_packets
            },
            'detection_metrics': metrics,
            'detection_summary': summary,
            'packet_classifications': {
                'covert_count': sum(1 for p in self.captured_packets if p['is_likely_covert']),
                'legitimate_count': sum(1 for p in self.captured_packets if not p['is_likely_covert'])
            }
        }
        
        # Save results
        results_file = f"benchmark_results/detection_session_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"Detailed results saved to: {results_file}")

class DetectorManager:
    """Manager for running detection experiments"""
    
    def __init__(self):
        self.detectors = []
    
    async def run_detection_experiment(self, 
                                          threshold: float = 0.5,
                                          entropy_threshold: float = 0.3,
                                          duration: int = 120):
        """Run a single detection experiment"""
        
        print(f"Starting detection experiment:")
        print(f"  Threshold: {threshold}")
        print(f"  Entropy Threshold: {entropy_threshold}")
        print(f"  Duration: {duration} seconds")
        print()
        print("INSTRUCTIONS:")
        print("1. In insec container, start the TPPhase2 receiver:")
        print("   python3 tppphase2_receiver.py --decrypt --bits 16")
        print("2. In sec container, start the TPPhase2 sender:")
        print("   python3 tppphase2_sender.py --file secret_message.txt --encrypt --bits 16")
        print("3. This detector will monitor the traffic and report results")
        print()

        detector = NATSDetector(
            threshold=threshold,
            entropy_threshold=entropy_threshold,
            monitoring_duration=duration
        )
        
        try:
            await detector.start_monitoring()
        except KeyboardInterrupt:
            print("\nMonitoring interrupted by user")
            await detector.stop_monitoring()

async def main():
    """Main execution"""
    
    print("Covert Channel Detector")
    print("=" * 40)
    print("This tool monitors NATS traffic for covert channels")
    print("while TPPhase2 sender/receiver are running")
    print()
    
    # Get configuration from user or use defaults
    threshold = float(os.getenv("DETECTOR_THRESHOLD", "0.5"))
    entropy_threshold = float(os.getenv("DETECTOR_ENTROPY_THRESHOLD", "0.3"))
    duration = int(os.getenv("MONITORING_DURATION", "120"))
    
    manager = DetectorManager()
    
    try:
        await manager.run_detection_experiment(
            threshold=threshold,
            entropy_threshold=entropy_threshold,
            duration=duration
        )
    except KeyboardInterrupt:
        print("\nShutting down detector...")

if __name__ == "__main__":
    asyncio.run(main())