#!/usr/bin/env python3
"""
Covert Channel Detector - Detects TCP Urgent Pointer covert channels
Based on RFC violations and statistical anomaly detection
"""

import time
import statistics
from typing import List, Dict, Tuple, Optional, NamedTuple
import numpy as np
from scapy.all import Ether, IP, TCP
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum

class AnomalyType(Enum):
    URG_POINTER_WITHOUT_FLAG = "URG_POINTER_WITHOUT_FLAG"
    URG_POINTER_BEYOND_DATA = "URG_POINTER_BEYOND_DATA"
    HIGH_URG_ENTROPY = "HIGH_URG_ENTROPY"
    URG_POINTER_IN_ASCII_RANGE = "URG_POINTER_IN_ASCII_RANGE"

@dataclass
class PacketAnalysis:
    timestamp: float
    is_anomalous: bool
    confidence: float
    anomaly_reasons: List[str]
    urg_pointer: int = 0
    has_urg_flag: bool = False
    payload_length: int = 0

class CovertChannelDetector:
    """Detects covert channels in TCP Urgent Pointer field"""
    
    def __init__(self, 
                 anomaly_threshold: float = 0.5,
                 urg_entropy_threshold: float = 0.5,
                 window_size: int = 50):
        
        self.anomaly_threshold = anomaly_threshold
        self.urg_entropy_threshold = urg_entropy_threshold
        self.window_size = window_size
        
        # Statistics tracking
        self.urg_values = deque(maxlen=window_size)
        self.packet_count = 0
        self.anomaly_count = 0
        
        # Detection tracking for metrics
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0
        
        # Connection tracking
        self.connections = defaultdict(lambda: {
            'urg_values': deque(maxlen=20),
            'packet_count': 0,
            'anomaly_count': 0
        })
    
    def analyze_packet(self, packet_data: bytes, timestamp: float, is_covert: bool = None) -> Optional[PacketAnalysis]:
        """Analyze a packet for covert channel indicators"""
        
        try:
            packet = Ether(packet_data)
            if not (IP in packet and TCP in packet):
                return None
            
            tcp_layer = packet[TCP]
            ip_layer = packet[IP]
            
            # Extract packet information
            urg_pointer = tcp_layer.urgptr
            has_urg_flag = bool(tcp_layer.flags & 0x20)  # URG flag
            payload_length = len(tcp_layer.payload) if tcp_layer.payload else 0
            
            # Connection key
            conn_key = f"{ip_layer.src}:{tcp_layer.sport}->{ip_layer.dst}:{tcp_layer.dport}"
            
            # Update statistics
            self.packet_count += 1
            self.urg_values.append(urg_pointer)
            
            # Connection-specific tracking
            conn_stats = self.connections[conn_key]
            conn_stats['packet_count'] += 1
            conn_stats['urg_values'].append(urg_pointer)
            
            # Perform anomaly detection
            anomalies = []
            confidence = 0.0
            
            # Rule 1: URG pointer without URG flag (RFC violation)
            if urg_pointer > 0 and not has_urg_flag:
                anomalies.append(AnomalyType.URG_POINTER_WITHOUT_FLAG.value)
                confidence += 0.8
            
            # Rule 2: URG pointer beyond data (when URG flag is set)
            if has_urg_flag and urg_pointer > payload_length and payload_length > 0:
                anomalies.append(AnomalyType.URG_POINTER_BEYOND_DATA.value)
                confidence += 0.7
            
            # Rule 3: URG pointer in ASCII range (suggests character encoding)
            if 32 <= urg_pointer <= 126:
                anomalies.append(AnomalyType.URG_POINTER_IN_ASCII_RANGE.value)
                confidence += 0.3
            
            # Rule 4: High entropy in URG values (statistical anomaly)
            if len(self.urg_values) >= 10:
                entropy = self.calculate_entropy(list(self.urg_values)[-10:])
                if entropy > self.urg_entropy_threshold:
                    anomalies.append(AnomalyType.HIGH_URG_ENTROPY.value)
                    confidence += 0.4
            
            # Normalize confidence
            confidence = min(confidence, 1.0)
            
            # Determine if anomalous
            is_anomalous = confidence >= self.anomaly_threshold
            
            if is_anomalous:
                self.anomaly_count += 1
                conn_stats['anomaly_count'] += 1
            
            # Update metrics if ground truth is provided
            if is_covert is not None:
                if is_anomalous and is_covert:
                    self.true_positives += 1
                elif is_anomalous and not is_covert:
                    self.false_positives += 1
                elif not is_anomalous and is_covert:
                    self.false_negatives += 1
                else:
                    self.true_negatives += 1
            
            return PacketAnalysis(
                timestamp=timestamp,
                is_anomalous=is_anomalous,
                confidence=confidence,
                anomaly_reasons=anomalies,
                urg_pointer=urg_pointer,
                has_urg_flag=has_urg_flag,
                payload_length=payload_length
            )
            
        except Exception as e:
            return None
    
    def calculate_entropy(self, values: List[int]) -> float:
        """Calculate entropy of URG pointer values"""
        if not values:
            return 0.0
        
        # Count frequency of each value
        from collections import Counter
        counts = Counter(values)
        total = len(values)
        
        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        
        # Normalize by max possible entropy
        max_entropy = np.log2(len(counts)) if len(counts) > 1 else 1
        return entropy / max_entropy if max_entropy > 0 else 0
    
    def get_detection_metrics(self) -> Dict:
        """Calculate detection performance metrics"""
        
        tp = self.true_positives
        tn = self.true_negatives
        fp = self.false_positives
        fn = self.false_negatives
        
        total = tp + tn + fp + fn
        if total == 0:
            return {}
        
        # Calculate metrics
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'fpr': fpr,
            'tp': tp,
            'tn': tn,
            'fp': fp,
            'fn': fn,
            'total_packets': total
        }
    
    def get_summary_stats(self) -> Dict:
        """Get summary statistics"""
        
        anomaly_rate = self.anomaly_count / self.packet_count if self.packet_count > 0 else 0
        
        stats = {
            'total_packets': self.packet_count,
            'anomalies_detected': self.anomaly_count,
            'anomaly_rate': anomaly_rate,
            'active_connections': len(self.connections)
        }
        
        if self.urg_values:
            stats.update({
                'urg_mean': np.mean(self.urg_values),
                'urg_std': np.std(self.urg_values),
                'urg_min': np.min(self.urg_values),
                'urg_max': np.max(self.urg_values),
                'urg_entropy': self.calculate_entropy(list(self.urg_values))
            })
        
        return stats
    
    def reset_metrics(self):
        """Reset detection metrics"""
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0
        self.packet_count = 0
        self.anomaly_count = 0
        self.urg_values.clear()
        self.connections.clear()

if __name__ == "__main__":
    # Simple test
    detector = CovertChannelDetector()
    print("Covert Channel Detector initialized successfully")
    print(f"Anomaly threshold: {detector.anomaly_threshold}")
    print(f"Entropy threshold: {detector.urg_entropy_threshold}")