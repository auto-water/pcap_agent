#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSecAnalyzer - 工具函数和常量定义
提供项目所需的辅助函数、常量和配置
"""

import json
import logging
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional
import colorlog

# 项目常量定义
class Constants:
    """项目常量"""
    
    # 攻击类型定义
    ATTACK_TYPES = {
        'PORT_SCAN': '端口扫描',
        'ADDRESS_SCAN': '地址扫描', 
        'FLOODING': '泛洪攻击',
        'SYN_FLOOD': 'SYN泛洪',
        'UDP_FLOOD': 'UDP泛洪',
        'ICMP_FLOOD': 'ICMP泛洪',
        'ANOMALOUS_TRAFFIC': '异常流量',
        'SUSPICIOUS_BEHAVIOR': '可疑行为'
    }
    
    # 协议类型
    PROTOCOLS = {
        1: 'ICMP',
        6: 'TCP', 
        17: 'UDP',
        47: 'GRE',
        50: 'ESP',
        51: 'AH'
    }
    
    # 检测阈值
    THRESHOLDS = {
        'PORT_SCAN_THRESHOLD': 10,      # 端口扫描检测阈值
        'ADDRESS_SCAN_THRESHOLD': 50,   # 地址扫描检测阈值
        'FLOOD_THRESHOLD': 100,         # 泛洪攻击检测阈值
        'TIME_WINDOW': 60,              # 时间窗口（秒）
        'MIN_PACKET_SIZE': 64,          # 最小数据包大小
        'MAX_PACKET_SIZE': 1500         # 最大数据包大小
    }
    
    # 日志级别
    LOG_LEVELS = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }


def setup_logger(name: str, level: str = 'INFO') -> logging.Logger:
    """
    设置彩色日志记录器
    
    Args:
        name: 日志记录器名称
        level: 日志级别
        
    Returns:
        配置好的日志记录器
    """
    logger = logging.getLogger(name)
    logger.setLevel(Constants.LOG_LEVELS.get(level, logging.INFO))
    
    # 避免重复添加处理器
    if logger.handlers:
        return logger
    
    # 创建控制台处理器
    console_handler = colorlog.StreamHandler()
    console_handler.setLevel(Constants.LOG_LEVELS.get(level, logging.INFO))
    
    # 设置彩色格式
    color_formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white'
        }
    )
    console_handler.setFormatter(color_formatter)
    logger.addHandler(console_handler)
    
    # 创建文件处理器
    file_handler = logging.FileHandler(f'netsec_analyzer_{datetime.now().strftime("%Y%m%d")}.log', 
                                     encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # 文件格式（不包含颜色代码）
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger


def validate_ip_address(ip: str) -> bool:
    """
    验证IP地址格式
    
    Args:
        ip: 要验证的IP地址字符串
        
    Returns:
        如果是有效的IP地址返回True，否则返回False
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """
    验证端口号范围
    
    Args:
        port: 要验证的端口号
        
    Returns:
        如果是有效端口号返回True，否则返回False
    """
    return 1 <= port <= 65535


def format_bytes(bytes_size: int) -> str:
    """
    格式化字节大小为人类可读的格式
    
    Args:
        bytes_size: 字节大小
        
    Returns:
        格式化后的字符串
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} TB"


def format_timestamp(timestamp: float) -> str:
    """
    格式化时间戳为可读格式
    
    Args:
        timestamp: Unix时间戳
        
    Returns:
        格式化的时间字符串
    """
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


def create_attack_report(attack_type: str, 
                        source_ip: str, 
                        dest_ip: str, 
                        details: Dict[str, Any]) -> Dict[str, Any]:
    """
    创建攻击报告结构
    
    Args:
        attack_type: 攻击类型
        source_ip: 源IP地址
        dest_ip: 目标IP地址
        details: 详细信息
        
    Returns:
        结构化的攻击报告
    """
    return {
        'timestamp': datetime.now().isoformat(),
        'attack_type': attack_type,
        'attack_type_cn': Constants.ATTACK_TYPES.get(attack_type, '未知攻击'),
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'details': details,
        'severity': _calculate_severity(attack_type, details)
    }


def _calculate_severity(attack_type: str, details: Dict[str, Any]) -> str:
    """
    根据攻击类型和详情计算严重程度
    
    Args:
        attack_type: 攻击类型
        details: 攻击详情
        
    Returns:
        严重程度等级
    """
    packet_count = details.get('packet_count', 0)
    
    if attack_type in ['FLOODING', 'SYN_FLOOD', 'UDP_FLOOD', 'ICMP_FLOOD']:
        if packet_count > 1000:
            return 'CRITICAL'
        elif packet_count > 500:
            return 'HIGH'
        else:
            return 'MEDIUM'
    elif attack_type in ['PORT_SCAN', 'ADDRESS_SCAN']:
        if packet_count > 100:
            return 'HIGH'
        elif packet_count > 50:
            return 'MEDIUM'
        else:
            return 'LOW'
    else:
        return 'MEDIUM'


def save_analysis_result(results: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
    """
    保存分析结果到JSON文件
    
    Args:
        results: 分析结果列表
        filename: 保存文件名，如果为None则自动生成
        
    Returns:
        保存的文件路径
    """
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'netsec_analysis_{timestamp}.json'
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    return filename


def load_config(config_file: str = None) -> Dict[str, Any]:
    """
    加载配置文件
    
    Args:
        config_file: 配置文件路径
        
    Returns:
        配置字典
    """
    if config_file is None:
        config_file = 'config.yaml'
    
    try:
        import yaml
        with open(config_file, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        # 返回默认配置
        return {
            'fluidai': {
                'api_url': 'https://api.fluidai.com/v1/chat/completions',
                'api_key': 'your_api_key_here',
                'model': 'fluidai-pro',
                'timeout': 30
            },
            'analysis': {
                'enable_realtime': True,
                'packet_limit': 10000,
                'time_window': 60,
                'enable_ai_analysis': True
            },
            'logging': {
                'level': 'INFO',
                'file_enabled': True,
                'console_enabled': True
            }
        }
    except Exception as e:
        print(f"加载配置文件失败: {e}")
        # 返回默认配置而不是空字典
        return {
            'fluidai': {
                'api_url': 'https://api.fluidai.com/v1/chat/completions',
                'api_key': 'your_api_key_here',
                'model': 'fluidai-pro',
                'timeout': 30
            },
            'analysis': {
                'enable_realtime': True,
                'packet_limit': 10000,
                'time_window': 60,
                'enable_ai_analysis': True
            },
            'logging': {
                'level': 'INFO',
                'file_enabled': True,
                'console_enabled': True
            }
        }


def print_banner():
    """打印项目横幅"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    NetSecAnalyzer v1.0                       ║
    ║              智能网络安全分析工具                              ║
    ║              基于 PyPCAP 和硅基流动 AI                        ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


if __name__ == "__main__":
    # 测试函数
    print_banner()
    
    # 测试日志
    logger = setup_logger('test')
    logger.info("工具模块测试完成")
    
    # 测试IP验证
    print(f"IP地址 192.168.1.1 有效: {validate_ip_address('192.168.1.1')}")
    print(f"IP地址 999.999.999.999 有效: {validate_ip_address('999.999.999.999')}")
    
    # 测试格式化函数
    print(f"字节格式化: {format_bytes(1024)}")
    print(f"时间戳格式化: {format_timestamp(1640995200.123)}")