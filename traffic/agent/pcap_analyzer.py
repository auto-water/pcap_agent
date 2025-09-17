#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSecAnalyzer - 网络抓包与分析模块
使用 PyPCAP 库实现网络流量捕获、解析和分析功能
"""

import time
import struct
import socket
import threading
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# 全局变量
PCAPY_AVAILABLE = False
PCAPKIT_AVAILABLE = False
PYPCAP_AVAILABLE = False



from utils import (
    Constants, setup_logger, validate_ip_address, validate_port,
    format_bytes, format_timestamp, create_attack_report
)


class PacketInfo:
    """数据包信息类"""
    
    def __init__(self, timestamp: float, src_ip: str, dst_ip: str, 
                 src_port: int, dst_port: int, protocol: str, 
                 packet_size: int, payload: bytes = b''):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packet_size = packet_size
        self.payload = payload
        
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'packet_size': self.packet_size,
            'payload_size': len(self.payload)
        }
    
    def __str__(self) -> str:
        return (f"Packet[{self.protocol}] {self.src_ip}:{self.src_port} -> "
                f"{self.dst_ip}:{self.dst_port} ({self.packet_size} bytes)")


class TrafficAnalyzer:
    """流量分析器"""
    
    def __init__(self, time_window: int = 60, silent_mode: bool = False):
        self.time_window = time_window
        self.silent_mode = silent_mode
        self.packet_history = deque(maxlen=200000)  # 限制历史记录数量
        self.logger = setup_logger('TrafficAnalyzer')
        
    def add_packet(self, packet: PacketInfo, is_file_analysis: bool = False):
        """添加数据包进行分析"""
        current_time = time.time()
        
        # 添加新数据包
        self.packet_history.append(packet)

    
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取流量统计信息"""
        if not self.packet_history:
            return {}
        
        stats = {
            'total_packets': len(self.packet_history),
            'protocols': defaultdict(int),
            'top_sources': defaultdict(int),
            'top_destinations': defaultdict(int),
            'packet_sizes': []
        }

        
        for packet in self.packet_history:
            stats['protocols'][packet.protocol] += 1
            stats['top_sources'][packet.src_ip] += 1
            stats['top_destinations'][packet.dst_ip] += 1
            stats['packet_sizes'].append(packet.packet_size)
            # dt_object = datetime.fromtimestamp(float(packet.timestamp))
            # print(f"Packet Time: {dt_object}, Info: {packet.timestamp}")
        
        if stats['packet_sizes']:
            stats['avg_packet_size'] = sum(stats['packet_sizes']) / len(stats['packet_sizes'])
            stats['min_packet_size'] = min(stats['packet_sizes'])
            stats['max_packet_size'] = max(stats['packet_sizes'])
        
        
        return stats

class PCAPAnalyzer:
    """PCAP 分析器主类"""
    
    def __init__(self, config: Dict[str, Any] = None, silent_mode: bool = False):
        self.config = config or {}
        self.silent_mode = silent_mode
        self.logger = setup_logger('PCAPAnalyzer')
        self.time_window = self.config.get('time_window', Constants.THRESHOLDS['TIME_WINDOW'])
        self.traffic_analyzer = TrafficAnalyzer(time_window=self.time_window, silent_mode=silent_mode)
        self.is_capturing = False
        self.capture_thread = None
        
    def parse_packet_pcapy(self, header: Any, data: bytes) -> Optional[PacketInfo]:
        """使用 pcapy 解析数据包"""
        try:
            # 解析以太网头部
            if len(data) < 14:
                return None
            
            eth_header = struct.unpack('!6s6sH', data[:14])
            eth_type = eth_header[2]
            
            if eth_type != 0x0800:  # 只处理IPv4
                return None
            
            # 解析IP头部
            ip_header = data[14:34]
            ip_data = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = ip_data[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            if version != 4:
                return None
            
            protocol = ip_data[6]
            src_ip = socket.inet_ntoa(ip_data[8])
            dst_ip = socket.inet_ntoa(ip_data[9])
            
            protocol_name = Constants.PROTOCOLS.get(protocol, f'Unknown({protocol})')
            
            # 解析传输层头部
            src_port = 0
            dst_port = 0
            
            if protocol == 6 or protocol == 17:  # TCP or UDP
                if len(data) >= 34 + 4:
                    transport_header = struct.unpack('!HH', data[34:38])
                    src_port = transport_header[0]
                    dst_port = transport_header[1]
            
            timestamp = header.getts()[0] + header.getts()[1] / 1000000.0
            
            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol_name,
                packet_size=len(data),
                payload=data[14 + (ihl * 4) + 4:]
            )
            
        except Exception as e:
            self.logger.debug(f"解析数据包失败: {e}")
            return None
    
    def parse_packet_scapy(self, packet: Any) -> Optional[PacketInfo]:
        """使用 scapy 解析数据包"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            protocol_name = Constants.PROTOCOLS.get(protocol, f'Unknown({protocol})')
            
            src_port = 0
            dst_port = 0
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
            
            return PacketInfo(
                timestamp=packet.time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol_name,
                packet_size=len(packet),
                payload=bytes(packet.payload) if packet.payload else b''
            )
            
        except Exception as e:
            self.logger.debug(f"Scapy解析数据包失败: {e}")
            return None
    
    def analyze_pcap_file(self, file_path: str) -> List[PacketInfo]:
        """分析PCAP文件"""
        if not self.silent_mode:
            self.logger.info(f"开始分析PCAP文件: {file_path}")
        
        packets = []
        
        
        # 使用 scapy 读取文件
        try:
            scapy_packets = rdpcap(file_path)
            total_packets = len(scapy_packets)
            
            if not self.silent_mode:
                self.logger.info(f"使用 scapy 读取到 {total_packets} 个数据包")
            
            # 显示进度条（仅在静默模式下或大文件时显示）
            if TQDM_AVAILABLE and (self.silent_mode or total_packets > 1000):
                progress_bar = tqdm(scapy_packets, desc="分析数据包", unit="包", 
                                    disable=self.silent_mode and total_packets < 1000)
                iterator = progress_bar
            else:
                iterator = scapy_packets
            
            for packet in iterator:
                packet_info = self.parse_packet_scapy(packet)
                if packet_info:
                    packets.append(packet_info)
                    self.traffic_analyzer.add_packet(packet_info, is_file_analysis=True)
            
            if not self.silent_mode:
                self.logger.info(f"分析完成，共处理 {len(packets)} 个有效数据包")
            return packets
                    
        except Exception as e:
            self.logger.error(f"读取文件失败: {e}")

        return packets
    
    def get_analysis_results(self) -> Dict[str, Any]:
        """获取分析结果"""
        stats = self.traffic_analyzer.get_statistics()
        
        return {
            'statistics': stats,
            'timestamp': datetime.now().isoformat(),
            'analysis_duration': self.time_window
        }
    
    def get_attack_patterns(self) -> List[Dict[str, Any]]:
        """获取检测到的攻击模式"""
        # 这里可以返回检测到的攻击模式
        # 实际实现中，这些信息会在检测时保存
        return []


if __name__ == "__main__":
    # 测试代码
    analyzer = PCAPAnalyzer()
    
    # 测试统计功能
    stats = analyzer.get_analysis_results()
    print("分析结果:", stats)