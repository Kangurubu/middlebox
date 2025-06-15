#!/usr/bin/env python3
"""
TPP Phase 4: Comprehensive TCP URG Pointer Covert Channel Mitigation
Advanced processor for detecting and mitigating TCP URG pointer covert channels
with real-time analysis, statistical anomaly detection, and performance benchmarking.
"""

import asyncio
import json
import os
import time
import statistics
import random
import math
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import numpy as np
from nats.aio.client import Client as NATS
from scapy.all import Ether, IP, TCP
from scipy import stats

# Configuration class for mitigation strategies
@dataclass
class MitigationConfig:
    mode: str = "normalize"  # normalize, clear, randomize
    detection_threshold: int = 5  # URG packets per second
    log_suspicious: bool = True
    block_suspicious: bool = False
    statistical_window: int = 1000  # packets
    entropy_threshold: float = 0.8
    clear_both_urg_flag_and_pointer: bool = False
    randomize_when_urg_zero: bool = True

# Detection result data structure
@dataclass
class DetectionResult:
    is_suspicious: bool
    confidence: float
    anomaly_type: str
    urg_flag: bool
    urg_pointer: int
    packet_size: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

# Performance metrics data structure
@dataclass
class PerformanceMetrics:
    total_packets: int = 0
    suspicious_packets: int = 0
    mitigation_actions: int = 0
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    throughput_impact: float = 0.0
    avg_latency: float = 0.0
    confidence_95_latency: float = 0.0

class URGCovertChannelMitigator:
    """Comprehensive TCP URG pointer covert channel mitigation system"""
    
    def __init__(self, config: MitigationConfig):
        self.config = config
        self.nc = None
        
        # Statistical tracking
        self.packet_buffer = deque(maxlen=config.statistical_window)
        self.urg_pointer_values = deque(maxlen=config.statistical_window)
        self.urg_flag_frequency = deque(maxlen=100)  # Track URG flag frequency
        self.processing_times = deque(maxlen=1000)
        
        # Detection counters
        self.total_packets = 0
        self.suspicious_packets = 0
        self.mitigation_actions = 0
        self.start_time = time.time()
        
        # Statistical analysis
        self.urg_entropy_history = deque(maxlen=100)
        self.markov_chain_transitions = defaultdict(lambda: defaultdict(int))
        self.previous_urg_pointer = None
        
        # Rate-based detection
        self.urg_rate_window = deque(maxlen=60)  # 60 second window
        self.last_rate_check = time.time()
        
        # Performance tracking
        self.metrics = PerformanceMetrics()
        self.detection_log = []
        
        # Covert channel capacity tracking
        self.channel_capacity_samples = []
        self.theoretical_capacity = 16  # bits per packet
        
        # Report counter
        self.report_counter = 0
        
        # Shutdown flag
        self.shutdown_requested = False
        
        print(f"URG Covert Channel Mitigator initialized")
        print(f"Mode: {config.mode}")
        print(f"Detection threshold: {config.detection_threshold} URG packets/sec")
        print(f"Statistical window: {config.statistical_window} packets")
        print(f"Entropy threshold: {config.entropy_threshold}")

    def update_tcp_checksum(self, packet):
        """Update TCP checksum after modifications"""
        if TCP in packet:
            del packet[TCP].chksum
            packet[TCP].chksum = None
        return packet

    async def connect_nats(self):
        """Connect to NATS server"""
        self.nc = NATS()
        nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
        await self.nc.connect(nats_url)
        print(f"Connected to NATS server: {nats_url}")

    def analyze_tcp_header(self, packet_data: bytes) -> Optional[Dict]:
        """Extract TCP header information for analysis"""
        try:
            packet = Ether(packet_data)
            if not (IP in packet and TCP in packet):
                return None
            
            tcp_layer = packet[TCP]
            ip_layer = packet[IP]
            
            return {
                'packet': packet,
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'urg_flag': bool(tcp_layer.flags & 0x20),
                'urg_pointer': tcp_layer.urgptr,
                'payload_length': len(tcp_layer.payload) if tcp_layer.payload else 0,
                'packet_size': len(packet_data),
                'flags': tcp_layer.sprintf("%TCP.flags%"),
                'seq_num': tcp_layer.seq,
                'ack_num': tcp_layer.ack
            }
            
        except Exception as e:
            return None

    def detect_covert_channel(self, tcp_info: Dict, timestamp: float) -> DetectionResult:
        """Comprehensive covert channel detection"""
        start_detection = time.time()
        
        is_suspicious = False
        confidence = 0.0
        anomaly_type = "none"
        
        urg_flag = tcp_info['urg_flag']
        urg_pointer = tcp_info['urg_pointer']
        
        # Primary detection: URG pointer set without URG flag
        if not urg_flag and urg_pointer != 0:
            is_suspicious = True
            confidence += 0.8
            anomaly_type = "urg_pointer_without_flag"
        
        # Secondary detection: Unusual URG pointer patterns
        if urg_flag and urg_pointer > 0:
            # Check if URG pointer is in ASCII range (potential data encoding)
            if 32 <= urg_pointer <= 126:
                is_suspicious = True
                confidence += 0.6
                anomaly_type = "ascii_range_urg_pointer"
            
            # Check for URG with minimal payload (suspicious)
            if tcp_info['payload_length'] <= 1:
                is_suspicious = True
                confidence += 0.5
                anomaly_type = "urg_minimal_payload"

        # Rate-based detection
        current_time = time.time()
        if current_time - self.last_rate_check >= 1.0:
            self.urg_rate_window.append(len([p for p in self.packet_buffer 
                                           if (p.get('urg_flag', False) or p.get('urg_pointer', 0) > 0) and 
                                           p.get('timestamp', 0) > current_time - 1.0]))
            self.last_rate_check = current_time
            
            if len(self.urg_rate_window) > 0:
                avg_rate = statistics.mean(self.urg_rate_window)
                if avg_rate > self.config.detection_threshold:
                    is_suspicious = True
                    confidence += 0.4
                    anomaly_type = "high_urg_rate"

        # Statistical anomaly detection
        if len(self.urg_pointer_values) > 50:
            # Calculate entropy of URG pointer values
            entropy = self.calculate_entropy(list(self.urg_pointer_values))
            self.urg_entropy_history.append(entropy)
            
            if entropy > self.config.entropy_threshold:
                is_suspicious = True
                confidence += 0.3
                anomaly_type = "high_entropy_urg"

        # Markov chain analysis for state transitions
        if self.previous_urg_pointer is not None:
            self.markov_chain_transitions[self.previous_urg_pointer][urg_pointer] += 1
            
            # Detect unusual transition patterns
            if len(self.markov_chain_transitions) > 10:
                transition_entropy = self.calculate_markov_entropy()
                if transition_entropy > 0.7:
                    is_suspicious = True
                    confidence += 0.2
                    anomaly_type = "unusual_transitions"

        self.previous_urg_pointer = urg_pointer
        
        # Normalize confidence to [0, 1]
        confidence = min(confidence, 1.0)
        
        detection_time = time.time() - start_detection
        self.processing_times.append(detection_time)
        
        return DetectionResult(
            is_suspicious=is_suspicious,
            confidence=confidence,
            anomaly_type=anomaly_type,
            urg_flag=urg_flag,
            urg_pointer=urg_pointer,
            packet_size=tcp_info['packet_size'],
            timestamp=timestamp,
            src_ip=tcp_info['src_ip'],
            dst_ip=tcp_info['dst_ip'],
            src_port=tcp_info['src_port'],
            dst_port=tcp_info['dst_port']
        )

    def apply_mitigation(self, packet, tcp_info: Dict, detection: DetectionResult) -> bytes:
        """Apply configured mitigation strategy"""
        modified_packet = packet.copy()
        tcp_layer = modified_packet[TCP]
        
        mitigation_applied = False
        
        if self.config.mode == "normalize":
            # Mode 1: Clear urgent pointer when URG=0
            if not detection.urg_flag and detection.urg_pointer != 0:
                tcp_layer.urgptr = 0
                mitigation_applied = True
                
        elif self.config.mode == "clear":
            # Mode 2: Clear both URG flag and pointer completely
            if detection.urg_flag or detection.urg_pointer != 0:
                tcp_layer.flags = tcp_layer.flags & ~0x20  # Clear URG flag
                tcp_layer.urgptr = 0
                mitigation_applied = True
                
        elif self.config.mode == "randomize":
            # Mode 3: Randomize urgent pointer when URG=0
            if not detection.urg_flag and detection.urg_pointer != 0:
                tcp_layer.urgptr = random.randint(0, 65535)
                mitigation_applied = True
            elif detection.is_suspicious:
                # Randomize suspicious URG pointers
                tcp_layer.urgptr = random.randint(0, 65535)
                mitigation_applied = True

        if mitigation_applied:
            self.mitigation_actions += 1
            modified_packet = self.update_tcp_checksum(modified_packet)
            
        return bytes(modified_packet)

    def calculate_entropy(self, values: List[int]) -> float:
        """Calculate Shannon entropy of URG pointer values"""
        if not values:
            return 0.0
        
        # Count frequencies
        freq_map = defaultdict(int)
        for val in values:
            freq_map[val] += 1
        
        # Calculate entropy
        total = len(values)
        entropy = 0.0
        for count in freq_map.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
                
        return entropy

    def calculate_markov_entropy(self) -> float:
        """Calculate entropy of Markov chain transitions"""
        if not self.markov_chain_transitions:
            return 0.0
        
        total_transitions = sum(sum(transitions.values()) 
                              for transitions in self.markov_chain_transitions.values())
        
        if total_transitions == 0:
            return 0.0
        
        entropy = 0.0
        for state_transitions in self.markov_chain_transitions.values():
            state_total = sum(state_transitions.values())
            if state_total == 0:
                continue
                
            for count in state_transitions.values():
                p = count / state_total
                if p > 0:
                    entropy -= p * math.log2(p)
        
        return entropy / len(self.markov_chain_transitions)

    def calculate_channel_capacity(self, detection_rate: float, packet_rate: float) -> Dict:
        """Calculate covert channel capacity metrics"""
        # Theoretical capacity: 16 bits per packet
        theoretical_bps = packet_rate * self.theoretical_capacity
        
        # Actual capacity after detection/mitigation
        actual_bps = theoretical_bps * (1 - detection_rate)
        
        # Bandwidth reduction
        bandwidth_reduction = (theoretical_bps - actual_bps) / theoretical_bps if theoretical_bps > 0 else 0
        
        return {
            'theoretical_capacity_bps': theoretical_bps,
            'actual_capacity_bps': actual_bps,
            'bandwidth_reduction': bandwidth_reduction,
            'detection_rate': detection_rate,
            'capacity_utilization': actual_bps / theoretical_bps if theoretical_bps > 0 else 0
        }

    def update_statistics(self, tcp_info: Dict, detection: DetectionResult, timestamp: float):
        """Update statistical tracking"""
        # Add packet to buffer
        packet_data = {
            'timestamp': timestamp,
            'urg_flag': tcp_info['urg_flag'],
            'urg_pointer': tcp_info['urg_pointer'],
            'packet_size': tcp_info['packet_size'],
            'is_suspicious': detection.is_suspicious
        }
        self.packet_buffer.append(packet_data)
        
        # Track URG pointer values
        self.urg_pointer_values.append(tcp_info['urg_pointer'])
        
        # Update counters
        self.total_packets += 1
        if detection.is_suspicious:
            self.suspicious_packets += 1

    def get_performance_metrics(self) -> PerformanceMetrics:
        """Calculate current performance metrics"""
        current_time = time.time()
        runtime = current_time - self.start_time
        
        # Calculate rates
        detection_rate = self.suspicious_packets / self.total_packets if self.total_packets > 0 else 0
        false_positive_rate = 0.1  # Estimate - would need ground truth for exact calculation
        
        # Calculate latency statistics
        if self.processing_times:
            avg_latency = statistics.mean(self.processing_times) * 1000  # Convert to ms
            sorted_times = sorted(self.processing_times)
            idx_95 = int(0.95 * len(sorted_times))
            confidence_95_latency = sorted_times[idx_95] * 1000 if idx_95 < len(sorted_times) else avg_latency
        else:
            avg_latency = 0.0
            confidence_95_latency = 0.0
        
        # Calculate throughput impact
        throughput_impact = (self.mitigation_actions / self.total_packets) if self.total_packets > 0 else 0
        
        self.metrics = PerformanceMetrics(
            total_packets=self.total_packets,
            suspicious_packets=self.suspicious_packets,
            mitigation_actions=self.mitigation_actions,
            detection_rate=detection_rate,
            false_positive_rate=false_positive_rate,
            throughput_impact=throughput_impact,
            avg_latency=avg_latency,
            confidence_95_latency=confidence_95_latency
        )
        
        return self.metrics

    def generate_report(self, packet_count: int = 1000) -> Dict:
        """Generate comprehensive analysis report"""
        metrics = self.get_performance_metrics()
        current_time = time.time()
        runtime = current_time - self.start_time
        
        # Calculate packet rate
        packet_rate = self.total_packets / runtime if runtime > 0 else 0
        
        # Calculate channel capacity
        capacity_metrics = self.calculate_channel_capacity(metrics.detection_rate, packet_rate)
        
        # Statistical analysis
        entropy_stats = {}
        if self.urg_entropy_history:
            entropy_stats = {
                'mean_entropy': statistics.mean(self.urg_entropy_history),
                'max_entropy': max(self.urg_entropy_history),
                'min_entropy': min(self.urg_entropy_history),
                'entropy_variance': statistics.variance(self.urg_entropy_history) if len(self.urg_entropy_history) > 1 else 0
            }
        
        # URG pointer distribution
        urg_distribution = {}
        if self.urg_pointer_values:
            unique_values = set(self.urg_pointer_values)
            total_urgs = len(self.urg_pointer_values)
            urg_distribution = {
                'unique_values': len(unique_values),
                'zero_percentage': (list(self.urg_pointer_values).count(0) / total_urgs) * 100,
                'non_zero_percentage': ((total_urgs - list(self.urg_pointer_values).count(0)) / total_urgs) * 100,
                'max_value': max(self.urg_pointer_values),
                'mean_value': statistics.mean(self.urg_pointer_values)
            }
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'runtime_seconds': runtime,
            'configuration': asdict(self.config),
            'performance_metrics': asdict(metrics),
            'channel_capacity': capacity_metrics,
            'statistical_analysis': {
                'entropy_analysis': entropy_stats,
                'urg_pointer_distribution': urg_distribution,
                'packet_rate_pps': packet_rate
            },
            'detection_summary': {
                'total_detections': len(self.detection_log),
                'high_confidence_detections': len([d for d in self.detection_log if d.confidence > 0.7]),
                'anomaly_types': self.get_anomaly_type_distribution()
            }
        }
        
        return report

    def get_anomaly_type_distribution(self) -> Dict[str, int]:
        """Get distribution of detected anomaly types"""
        distribution = defaultdict(int)
        for detection in self.detection_log:
            distribution[detection.anomaly_type] += 1
        return dict(distribution)

    def detect_finish_signal(self, tcp_info: Dict) -> bool:
        """Detect TPP Phase 2 finish signal packet"""
        try:
            # Check for finish signal: URG pointer = 0xDEAD
            if (tcp_info['urg_pointer'] == 0xDEAD and 
                tcp_info['dst_port'] == 8888):
                
                # Check payload for finish message
                packet = tcp_info['packet']
                if TCP in packet and packet[TCP].payload:
                    payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
                    if "COVERT_CHANNEL_FINISHED" in payload:
                        return True
            return False
        except:
            return False

    async def packet_handler(self, msg):
        """Main packet processing handler"""
        try:
            start_time = time.time()
            subject = msg.subject
            data = msg.data
            timestamp = time.time()
            
            # Analyze TCP header
            tcp_info = self.analyze_tcp_header(data)
            if not tcp_info:
                # Forward non-TCP packets unchanged
                out_topic = "outpktinsec" if subject == "inpktsec" else "outpktsec"
                await self.nc.publish(out_topic, data)
                return
            
            # Check for finish signal packet first
            is_finish_packet = self.detect_finish_signal(tcp_info)
            
            if is_finish_packet:
                print(f"\n[FINISH SIGNAL] Detected covert channel completion!")
                print(f"URG pointer: 0x{tcp_info['urg_pointer']:04X}, Port: {tcp_info['dst_port']}")
                
                # Forward the finish packet immediately
                out_topic = "outpktinsec" if subject == "inpktsec" else "outpktsec"
                
                # Update packet stats before forwarding
                self.total_packets += 1
                
                try:
                    # Update TCP checksum and forward
                    packet = tcp_info['packet']
                    packet = self.update_tcp_checksum(packet)
                    await self.nc.publish(out_topic, bytes(packet))
                    print(f"[FINISH SIGNAL] Forwarded finish packet to receiver")
                except:
                    # If packet modification fails, forward original
                    await self.nc.publish(out_topic, data)
                    print(f"[FINISH SIGNAL] Forwarded original finish packet to receiver")
                
                # Generate final report
                print(f"\n[INFO] Generating final mitigation report...")
                await asyncio.sleep(1)  # Brief delay to ensure packet delivery
                
                final_report = self.generate_report()
                self.save_report(final_report)
                self.print_final_summary()
                
                print(f"\n[INFO] URG covert channel mitigation session completed.")
                print(f"[INFO] Check benchmark_results/ for detailed analysis.")
                
                # Set shutdown flag to trigger graceful exit
                self.shutdown_requested = True
                return
            
            # Perform covert channel detection for regular packets
            detection = self.detect_covert_channel(tcp_info, timestamp)
            
            # Update statistics
            self.update_statistics(tcp_info, detection, timestamp)
            
            # Log detection if suspicious
            if detection.is_suspicious:
                self.detection_log.append(detection)
                
                if self.config.log_suspicious:
                    src_name = "sec" if tcp_info['src_ip'].startswith('10.1') else "insec"
                    dst_name = "insec" if tcp_info['dst_ip'].startswith('10.0') else "sec"
                    
                    print(f"[DETECTION] {detection.anomaly_type} | "
                          f"Conf: {detection.confidence:.3f} | "
                          f"{src_name}:{detection.src_port} -> "
                          f"{dst_name}:{detection.dst_port} | "
                          f"URG={detection.urg_pointer} | "
                          f"Flag={'Y' if detection.urg_flag else 'N'}")
            
            # Apply mitigation if needed
            if detection.is_suspicious and not self.config.block_suspicious:
                processed_data = self.apply_mitigation(tcp_info['packet'], tcp_info, detection)
            elif self.config.block_suspicious and detection.is_suspicious:
                # Block packet - don't forward
                print(f"[BLOCKED] Suspicious packet blocked: {detection.anomaly_type}")
                return
            else:
                # Forward packet unchanged
                processed_data = data
            
            # Forward processed packet
            out_topic = "outpktinsec" if subject == "inpktsec" else "outpktsec"
            await self.nc.publish(out_topic, processed_data)
            
            # Generate periodic status updates (but not reports)
            if self.total_packets % 500 == 0:  # More frequent status updates
                self.print_status_update()
            
        except Exception as e:
            print(f"Error in packet handler: {e}")
            # Forward packet on error to maintain connectivity
            try:
                out_topic = "outpktinsec" if msg.subject == "inpktsec" else "outpktsec"
                await self.nc.publish(out_topic, msg.data)
            except:
                pass

    def print_status_update(self):
        """Print real-time status update"""
        metrics = self.get_performance_metrics()
        runtime = time.time() - self.start_time
        
        print(f"\n{'='*70}")
        print(f"URG COVERT CHANNEL MITIGATION - STATUS UPDATE #{self.report_counter + 1}")
        print(f"{'='*70}")
        print(f"Runtime: {runtime:.1f}s | Packets: {metrics.total_packets} | "
              f"Suspicious: {metrics.suspicious_packets} ({metrics.detection_rate:.3f})")
        print(f"Mitigations: {metrics.mitigation_actions} | "
              f"Latency: {metrics.avg_latency:.3f}ms (95%: {metrics.confidence_95_latency:.3f}ms)")
        
        if self.urg_entropy_history:
            current_entropy = self.urg_entropy_history[-1]
            print(f"URG Entropy: {current_entropy:.3f} | ", end="")
        
        # Show channel capacity impact
        packet_rate = metrics.total_packets / runtime if runtime > 0 else 0
        capacity = self.calculate_channel_capacity(metrics.detection_rate, packet_rate)
        print(f"Capacity Reduction: {capacity['bandwidth_reduction']:.1%}")
        
        # Show top anomaly types
        anomaly_dist = self.get_anomaly_type_distribution()
        if anomaly_dist:
            top_anomalies = sorted(anomaly_dist.items(), key=lambda x: x[1], reverse=True)[:3]
            print(f"Top Anomalies: {', '.join([f'{t}({c})' for t, c in top_anomalies])}")
        
        print(f"{'='*70}")

    def save_report(self, report: Dict):
        """Save JSON report to file"""
        os.makedirs("benchmark_results", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"benchmark_results/urg_mitigation_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Detailed results saved to: {filename}")
        self.report_counter += 1

    async def start_mitigation(self):
        """Start the URG covert channel mitigation system"""
        await self.connect_nats()
        
        # Subscribe to packet topics
        await self.nc.subscribe("inpktsec", cb=self.packet_handler)
        await self.nc.subscribe("inpktinsec", cb=self.packet_handler)
        
        print(f"\nURG Covert Channel Mitigation System Started")
        print(f"Mode: {self.config.mode}")
        print(f"Monitoring for URG pointer covert channels...")
        print(f"All packets are forwarded (transparent mode)")
        print(f"Will run until TPP Phase 2 finish signal received")
        print("-" * 70)
        
        try:
            while not self.shutdown_requested:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down mitigation system...")
        
        # Close NATS connection
        print(f"[INFO] Closing NATS connection...")
        try:
            await asyncio.wait_for(self.nc.close(), timeout=2.0)
        except asyncio.TimeoutError:
            print(f"[WARNING] NATS close timed out")
        except:
            print(f"[WARNING] NATS close failed")
        
        # Generate final report if not already done
        if not self.shutdown_requested:
            final_report = self.generate_report()
            self.save_report(final_report)
            self.print_final_summary()

    def print_final_summary(self):
        """Print final summary statistics"""
        metrics = self.get_performance_metrics()
        runtime = time.time() - self.start_time
        
        print(f"\n{'='*70}")
        print(f"FINAL URG COVERT CHANNEL MITIGATION REPORT")
        print(f"{'='*70}")
        print(f"Total Runtime: {runtime:.1f} seconds")
        print(f"Total Packets Processed: {metrics.total_packets}")
        print(f"Suspicious Packets Detected: {metrics.suspicious_packets}")
        print(f"Detection Rate: {metrics.detection_rate:.3f}")
        print(f"Mitigation Actions Taken: {metrics.mitigation_actions}")
        print(f"Average Processing Latency: {metrics.avg_latency:.3f}ms")
        print(f"95% Confidence Interval Latency: {metrics.confidence_95_latency:.3f}ms")
        
        # Channel capacity analysis
        packet_rate = metrics.total_packets / runtime if runtime > 0 else 0
        capacity = self.calculate_channel_capacity(metrics.detection_rate, packet_rate)
        
        print(f"\nCOVERT CHANNEL CAPACITY ANALYSIS:")
        print(f"Theoretical Capacity: {capacity['theoretical_capacity_bps']:.1f} bps")
        print(f"Actual Capacity (post-mitigation): {capacity['actual_capacity_bps']:.1f} bps")
        print(f"Bandwidth Reduction: {capacity['bandwidth_reduction']:.1%}")
        
        # Anomaly type distribution
        anomaly_dist = self.get_anomaly_type_distribution()
        if anomaly_dist:
            print(f"\nDETECTED ANOMALY TYPES:")
            for anomaly_type, count in sorted(anomaly_dist.items(), key=lambda x: x[1], reverse=True):
                print(f"  {anomaly_type}: {count}")

async def main():
    """Main execution function"""
    print("TCP URG Pointer Covert Channel Mitigation System")
    print("=" * 70)
    print("Advanced mitigation processor for URG pointer covert channels")
    print("Compatible with TPP Phase 2 covert channel implementation")
    print()
    
    # Configuration from environment variables
    config = MitigationConfig(
        mode=os.getenv("MITIGATION_MODE", "normalize"),
        detection_threshold=int(os.getenv("DETECTION_THRESHOLD", "5")),
        log_suspicious=os.getenv("LOG_SUSPICIOUS", "true").lower() == "true",
        block_suspicious=os.getenv("BLOCK_SUSPICIOUS", "false").lower() == "true",
        statistical_window=int(os.getenv("STATISTICAL_WINDOW", "1000")),
        entropy_threshold=float(os.getenv("ENTROPY_THRESHOLD", "0.8"))
    )
    
    print(f"Configuration:")
    print(f"  Mitigation Mode: {config.mode}")
    print(f"  Detection Threshold: {config.detection_threshold} URG packets/sec")
    print(f"  Statistical Window: {config.statistical_window} packets")
    print(f"  Entropy Threshold: {config.entropy_threshold}")
    print(f"  Log Suspicious: {config.log_suspicious}")
    print(f"  Block Suspicious: {config.block_suspicious}")
    print()
    
    print("TESTING INSTRUCTIONS:")
    print("=" * 70)
    print("1. Start this mitigation processor first")
    print("2. In INSEC container: python3 tppphase2_receiver.py --decrypt --bits 16")
    print("3. In SEC container: python3 tppphase2_sender.py --file secret_message.txt --encrypt --bits 16")
    print("4. This processor will detect and mitigate URG covert channels")
    print()
    print("Alternative legitimate traffic test:")
    print("1. In INSEC container: python3 traffic_receiver.py")
    print("2. In SEC container: python3 traffic_generator.py")
    print("3. This will show baseline with no covert channels")
    print()
    print("Environment Variables (optional):")
    print("  MITIGATION_MODE=normalize|clear|randomize")
    print("  DETECTION_THRESHOLD=5")
    print("  STATISTICAL_WINDOW=1000")
    print("  ENTROPY_THRESHOLD=0.8")
    print("  LOG_SUSPICIOUS=true")
    print("  BLOCK_SUSPICIOUS=false")
    print("=" * 70)
    
    # Start mitigation system
    mitigator = URGCovertChannelMitigator(config)
    await mitigator.start_mitigation()

if __name__ == "__main__":
    asyncio.run(main())