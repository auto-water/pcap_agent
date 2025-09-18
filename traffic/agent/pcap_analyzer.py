#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSecAnalyzer - 网络抓包与分析模块
使用 PyPCAP 库实现网络流量捕获、解析和分析功能
"""

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
    Constants, setup_logger
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

class SliceInfo:
    """
    用于封装单个时间切片的流量统计信息。
    """
    def __init__(self, start_timestamp: int):
        """
        初始化SliceInfo实例。

        Args:
            start_timestamp: 该时间切片开始的Unix时间戳。
        """
        self.start_timestamp = start_timestamp
        # 统计信息
        self.tcp_count = 0
        self.udp_count = 0
        self.tcp_flags = {'ack': 0, 'syn': 0, 'rst': 0}
        self.tcp_ports = set()
        self.udp_ports = set()
    
    def to_dict(self) -> dict:
        """
        将实例数据转换为字典格式，方便序列化（如JSON）。
        """
        return {
            "start_timestamp": self.start_timestamp,
            "tcp_count": self.tcp_count,
            "udp_count": self.udp_count,
            "tcp_flags": self.tcp_flags,
            "tcp_ports": sorted(list(self.tcp_ports)),
            "udp_ports": sorted(list(self.udp_ports))
        }


class TrafficAnalyzer:
    """流量分析器"""
    
    def __init__(self, time_window: int = 60, silent_mode: bool = False):
        self.time_window = time_window
        self.silent_mode = silent_mode
        self.packet_history = deque(maxlen=200000)  # 限制历史记录数量
        self.slice_history = deque(maxlen=200000)  # 限制历史记录数量
        self.logger = setup_logger('TrafficAnalyzer')
    

    
    
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
    
    def extractSliceInfo(self, scapy_packets: Any) -> Optional[List[Dict]]:
            """
            分析scapy_packets, 统计切片信息
            """
            if not scapy_packets:
                return None

            traffic_data = {}
            start_time = scapy_packets[0].time
            for packet in scapy_packets:
                # 计算数据包所在的时间段（以5秒为单位）
                time_slot = int((packet.time - start_time) // self.time_window)
                
                # 初始化当前时间段的统计字典
                if time_slot not in traffic_data:
                    traffic_data[time_slot] = {
                        'time_slot': time_slot * self.time_window,
                        'tcp_count': 0,
                        'udp_count': 0,
                        'tcp_flags': {'ack': 0, 'syn': 0, 'rst': 0},
                        'tcp_ports': set(),
                        'udp_ports': set()
                    }

                # 检查协议层
                if packet.haslayer(TCP):
                    traffic_data[time_slot]['tcp_count'] += 1
                    tcp_layer = packet.getlayer(TCP)
                    
                    # 统计TCP Flags
                    if 'A' in str(tcp_layer.flags):
                        traffic_data[time_slot]['tcp_flags']['ack'] += 1
                    if 'S' in str(tcp_layer.flags):
                        traffic_data[time_slot]['tcp_flags']['syn'] += 1
                    if 'R' in str(tcp_layer.flags):
                        traffic_data[time_slot]['tcp_flags']['rst'] += 1
                    
                    # 记录端口
                    traffic_data[time_slot]['tcp_ports'].add(tcp_layer.sport)
                    traffic_data[time_slot]['tcp_ports'].add(tcp_layer.dport)

                elif packet.haslayer(UDP):
                    traffic_data[time_slot]['udp_count'] += 1
                    udp_layer = packet.getlayer(UDP)
                    
                    # 记录端口
                    traffic_data[time_slot]['udp_ports'].add(udp_layer.sport)
                    traffic_data[time_slot]['udp_ports'].add(udp_layer.dport)

            slices = list(traffic_data.values())
            return slices if slices else None

    def analyze_pcap_file(self, file_path: str) -> Tuple[List[PacketInfo], List[SliceInfo]]:
        """分析PCAP文件"""
        if not self.silent_mode:
            self.logger.info(f"开始分析PCAP文件: {file_path}")
        
        packets = []
        slices = []
        # 使用 scapy 读取文件
        try:
            scapy_packets = rdpcap(file_path)
            total_packets = len(scapy_packets)
            
            if not self.silent_mode:
                self.logger.info(f"使用 scapy 读取到 {total_packets} 个数据包")
            
            # PacketInfo Extract
            if TQDM_AVAILABLE and (self.silent_mode or total_packets > 1000):
                progress_bar = tqdm(scapy_packets, desc="Extracting packets info", unit="packets", 
                                    disable=self.silent_mode and total_packets < 1000)
                iterator = progress_bar
            else:
                iterator = scapy_packets
            
            for packet in iterator:
                packet_info = self.parse_packet_scapy(packet)
                if packet_info:
                    packets.append(packet_info)
                    self.traffic_analyzer.packet_history.append(packet_info)
            
            # SLiceInfo Extract
            slices = self.extractSliceInfo(scapy_packets)

            self.logger.info(f"分析完成，共统计 {len(slices)} 个时间片，每个时间片长度为 {self.time_window} 秒")
            return packets, slices
                    
        except Exception as e:
            self.logger.error(f"读取文件失败: {e}")
            return None, None
    
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
    analyzer.analyze_pcap_file("D:/llk_labs/proj/combine/pcap/traffic/agent/simple3.pcapng")