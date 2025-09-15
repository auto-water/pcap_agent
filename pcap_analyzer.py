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
_SHOW_LIB_INFO = True

def check_libraries(show_info: bool = True):
    """检查可用的库"""
    global PCAPY_AVAILABLE, PCAPKIT_AVAILABLE, PYPCAP_AVAILABLE, SCAPY_AVAILABLE, _SHOW_LIB_INFO
    _SHOW_LIB_INFO = show_info
    
    try:
        import pcapy
        PCAPY_AVAILABLE = True
        if _SHOW_LIB_INFO:
            print("✓ 检测到 pcapy 库")
    except ImportError:
        if _SHOW_LIB_INFO:
            print("⚠ pcapy 库不可用")

    try:
        import pcapkit
        PCAPKIT_AVAILABLE = True
        if _SHOW_LIB_INFO:
            print("✓ 检测到 pcapkit 库")
    except ImportError:
        if _SHOW_LIB_INFO:
            print("⚠ pcapkit 库不可用，请运行 pip install pcapkit")

    try:
        import pcap
        PYPCAP_AVAILABLE = True
        if _SHOW_LIB_INFO:
            print("✓ 检测到 pypcap 库")
    except ImportError:
        if _SHOW_LIB_INFO:
            print("⚠ pypcap 库不可用")

    if SCAPY_AVAILABLE and _SHOW_LIB_INFO:
        print("✓ 检测到 scapy 库")
    elif not SCAPY_AVAILABLE and _SHOW_LIB_INFO:
        print("⚠ scapy 库未安装，请运行 pip install scapy")

    # 检查是否有可用的PCAP库
    if not any([PCAPY_AVAILABLE, PCAPKIT_AVAILABLE, PYPCAP_AVAILABLE]):
        if _SHOW_LIB_INFO:
            print("❌ 警告: 没有可用的PCAP库，实时抓包功能将不可用")
            print("建议安装以下库之一:")
            print("  pip install pcapkit  # 推荐，跨平台兼容性好")
            print("  pip install pypcap   # 需要先安装 WinPcap/Npcap (Windows)")
            print("  pip install pcapy-ng # 可能有兼容性问题")

# 默认检查库（显示信息）
# check_libraries(True)

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
        self.port_scan_detector = PortScanDetector()
        self.address_scan_detector = AddressScanDetector()
        self.flood_detector = FloodDetector()
        self.logger = setup_logger('TrafficAnalyzer')
        
        # 攻击检测统计
        self.attack_summary = {
            'port_scans': 0,
            'address_scans': 0,
            'flood_attacks': 0,
            'total_attacks': 0
        }
        
    def add_packet(self, packet: PacketInfo, is_file_analysis: bool = False):
        """添加数据包进行分析"""
        current_time = time.time()
        
        # 如果是文件分析，不清理过期数据（因为都是历史数据）
        if not is_file_analysis:
            # 清理过期数据（仅用于实时抓包）
            while self.packet_history and self.packet_history[0].timestamp < current_time - self.time_window:
                self.packet_history.popleft()
        
        # 添加新数据包
        self.packet_history.append(packet)
        
        # 进行各种攻击检测
        self._detect_attacks(packet)
    
    def _detect_attacks(self, packet: PacketInfo):
        """检测各种攻击模式"""
        # 端口扫描检测
        port_scan_result = self.port_scan_detector.check_packet(packet, self.packet_history)
        if port_scan_result:
            self.attack_summary['port_scans'] += 1
            self.attack_summary['total_attacks'] += 1
            # 静默模式下不输出详细日志
            if not self.silent_mode and port_scan_result.get('packet_count', 0) > 50:
                self.logger.warning(f"检测到端口扫描: {port_scan_result}")
        
        # 地址扫描检测
        address_scan_result = self.address_scan_detector.check_packet(packet, self.packet_history)
        if address_scan_result:
            self.attack_summary['address_scans'] += 1
            self.attack_summary['total_attacks'] += 1
            # 静默模式下不输出详细日志
            if not self.silent_mode and address_scan_result.get('packet_count', 0) > 100:
                self.logger.warning(f"检测到地址扫描: {address_scan_result}")
        
        # 泛洪攻击检测
        flood_result = self.flood_detector.check_packet(packet, self.packet_history)
        if flood_result:
            self.attack_summary['flood_attacks'] += 1
            self.attack_summary['total_attacks'] += 1
            # 静默模式下不输出详细日志
            if not self.silent_mode and flood_result.get('packet_count', 0) > 1000:
                self.logger.warning(f"检测到泛洪攻击: {flood_result}")
    
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
        
        # 转换为普通字典并排序
        stats['protocols'] = dict(sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True))
        stats['top_sources'] = dict(sorted(stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:10])
        stats['top_destinations'] = dict(sorted(stats['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:10])
        
        if stats['packet_sizes']:
            stats['avg_packet_size'] = sum(stats['packet_sizes']) / len(stats['packet_sizes'])
            stats['min_packet_size'] = min(stats['packet_sizes'])
            stats['max_packet_size'] = max(stats['packet_sizes'])
        
        # 添加攻击统计信息
        stats['attack_summary'] = self.attack_summary.copy()
        
        return stats


class PortScanDetector:
    """端口扫描检测器"""
    
    def __init__(self, threshold: int = 10, time_window: int = 60):
        self.threshold = threshold
        self.time_window = time_window
        self.scan_attempts = defaultdict(lambda: defaultdict(set))
    
    def check_packet(self, packet: PacketInfo, packet_history: deque) -> Optional[Dict[str, Any]]:
        """检查数据包是否为端口扫描"""
        if packet.protocol not in ['TCP', 'UDP']:
            return None
        
        current_time = time.time()
        src_ip = packet.src_ip
        
        # 记录扫描尝试
        dst_ip = packet.dst_ip
        self.scan_attempts[src_ip][dst_ip].add(packet.dst_port)
        
        # 检查是否超过阈值
        for dst_ip, ports in self.scan_attempts[src_ip].items():
            if len(ports) >= self.threshold:
                return {
                    'attack_type': 'PORT_SCAN',
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'packet_count': len(ports),
                    'scanned_ports': list(ports),
                    'threshold': self.threshold
                }
        
        return None


class AddressScanDetector:
    """地址扫描检测器"""
    
    def __init__(self, threshold: int = 50, time_window: int = 60):
        self.threshold = threshold
        self.time_window = time_window
        self.scan_attempts = defaultdict(set)
    
    def check_packet(self, packet: PacketInfo, packet_history: deque) -> Optional[Dict[str, Any]]:
        """检查数据包是否为地址扫描"""
        if packet.protocol not in ['TCP', 'UDP', 'ICMP']:
            return None
        
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        
        # 记录扫描尝试
        self.scan_attempts[src_ip].add(dst_ip)
        
        # 检查是否超过阈值
        if len(self.scan_attempts[src_ip]) >= self.threshold:
            return {
                'attack_type': 'ADDRESS_SCAN',
                'source_ip': src_ip,
                'packet_count': len(self.scan_attempts[src_ip]),
                'scanned_addresses': list(self.scan_attempts[src_ip]),
                'threshold': self.threshold
            }
        
        return None


class FloodDetector:
    """泛洪攻击检测器"""
    
    def __init__(self, threshold: int = 100, time_window: int = 10):
        self.threshold = threshold
        self.time_window = time_window
        self.packet_counts = defaultdict(lambda: defaultdict(int))
    
    def check_packet(self, packet: PacketInfo, packet_history: deque) -> Optional[Dict[str, Any]]:
        """检查数据包是否为泛洪攻击"""
        current_time = time.time()
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        
        # 清理过期计数
        # 这里简化处理，实际应该基于时间窗口清理
        
        # 增加计数
        self.packet_counts[src_ip][dst_ip] += 1
        
        # 检查是否超过阈值
        if self.packet_counts[src_ip][dst_ip] >= self.threshold:
            return {
                'attack_type': 'FLOODING',
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'packet_count': self.packet_counts[src_ip][dst_ip],
                'threshold': self.threshold,
                'protocol': packet.protocol
            }
        
        return None


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
        
        # 优先使用 scapy，然后是 pcapkit，最后是 pcapy
        if SCAPY_AVAILABLE:
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
                    self.logger.info(f"使用 scapy 分析完成，共处理 {len(packets)} 个有效数据包")
                return packets
                        
            except Exception as e:
                self.logger.error(f"使用 scapy 读取文件失败: {e}")

        self.logger.error("没有可用的PCAP库来读取文件")
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