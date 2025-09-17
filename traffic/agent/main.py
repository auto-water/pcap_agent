#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSecAnalyzer - 主入口文件
智能网络安全分析工具，集成 PyPCAP 网络抓包和硅基流动 AI 分析
"""

import os
import sys
import time
import argparse
from typing import Dict, List, Any, Optional
from datetime import datetime

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import (
    setup_logger, print_banner, Constants, 
    save_analysis_result, load_config, format_bytes
)
from pcap_analyzer import PCAPAnalyzer, PacketInfo
from fluidai_client import FluidAIClient


class NetSecAnalyzer:
    """NetSecAnalyzer 主类"""
    
    def __init__(self, config_file: str = None, silent_mode: bool = False):
        """
        初始化 NetSecAnalyzer
        
        Args:
            config_file: 配置文件路径
            silent_mode: 静默模式，减少输出信息
        """
        self.silent_mode = silent_mode
        self.config = load_config(config_file)
        
        # 根据静默模式调整日志级别
        log_level = 'ERROR' if silent_mode else self.config.get('logging', {}).get('level', 'INFO')
        self.logger = setup_logger('NetSecAnalyzer', log_level)
        
        # 初始化组件
        self.pcap_analyzer = PCAPAnalyzer(self.config.get('analysis', {}), silent_mode=silent_mode)
        self.fluidai_client = None
        
        
        self.is_running = False
        self.analysis_results = []
        
        if not self.silent_mode:
            self.logger.info("NetSecAnalyzer 初始化完成")
    
    
    def _init_fluidai_client(self) -> bool:
        """
        初始化 FluidAI 客户端
            
        Returns:
            初始化是否成功
        """
        try:
            # 获取 FluidAI 的配置，如果不存在则使用空字典
            fluidai_config = self.config.get('fluidai', {})

            # 提取 api_key，如果不存在则使用默认值
            api_key = fluidai_config.get('api_key', 'your_api_key_here')

            # 检查 api_key 是否有效，避免使用默认值进行连接
            if api_key == 'your_api_key_here' or not api_key:
                self.logger.error("配置文件中未找到有效的 FluidAI API 密钥。")
                return False

            # 创建一个副本，用于传递其他配置参数，避免 api_key 被重复传递
            client_config = fluidai_config.copy()
            client_config.pop('api_key', None)

            self.fluidai_client = FluidAIClient(api_key=api_key, **client_config)
            self.logger.info("使用真实 FluidAI 客户端")

            # 测试连接
            if self.fluidai_client.test_connection():
                self.logger.info("FluidAI 客户端连接成功")
                return True
            else:
                self.logger.warning("FluidAI 客户端连接失败")
                return False
                
        except Exception as e:
            self.logger.error(f"初始化 FluidAI 客户端失败: {e}")
            return False
    
    def analyze_pcap_file(self, file_path: str, use_ai: bool = True, output_file: str = None) -> Dict[str, Any]:
        """
        分析PCAP文件
        
        Args:
            file_path: PCAP文件路径
            use_ai: 是否使用AI分析
            output_file: 输出文件路径
            
        Returns:
            分析结果
        """
        self.logger.info(f"开始分析PCAP文件: {file_path}")
        
        if not os.path.exists(file_path):
            self.logger.error(f"文件不存在: {file_path}")
            return {}
        
        # 分析PCAP文件
        packets = self.pcap_analyzer.analyze_pcap_file(file_path)
        
        if not packets:
            self.logger.warning("未解析到有效数据包")
            return {}
        
        # 获取统计信息
        stats = self.pcap_analyzer.get_analysis_results()
        
        result = {
            'file_path': file_path,
            'analysis_time': datetime.now().isoformat(),
            'packets_analyzed': len(packets),
            'statistics': stats.get('statistics', {}),
            'ai_analysis': None,
            'attack_patterns': []
        }
        
        # AI分析
        try:
            # 分析流量统计
            ai_result = self.fluidai_client.analyze_network_traffic(stats.get('statistics', {}))
            result['ai_analysis'] = ai_result
            
            # 分析数据包模式
            packet_dicts = [p.to_dict() for p in packets[:100]]
            attack_patterns = self.fluidai_client.detect_attack_patterns(packet_dicts)
            result['attack_patterns'] = attack_patterns
            
            self.logger.info("AI分析完成")
        except Exception as e:
            self.logger.error(f"AI分析失败: {e}")
            result['ai_analysis'] = {'error': str(e)}
        
        # 保存结果
        if output_file:
            save_analysis_result([result], output_file)
            self.logger.info(f"分析结果已保存到: {output_file}")
        
        return result
    
    def generate_analysis_summary(self, result: Dict[str, Any]) -> str:
        """
        生成分析结果摘要字符串
        
        Args:
            result: 分析结果
        
        Returns:
            返回汇总后的字符串
        """
        summary = []
        
        # 添加标题
        summary.append("\n" + "=" * 60)
        summary.append("网络流量分析结果摘要")
        summary.append("=" * 60)
        
        # 文件路径和抓包时间
        if 'file_path' in result:
            summary.append(f"分析文件: {result['file_path']}")
        
        if 'capture_time' in result:
            summary.append(f"抓包时间: {result['capture_time']}")
        
        summary.append(f"分析时间: {result.get('analysis_time', result.get('capture_time', 'N/A'))}")
        
        # 流量统计
        stats = result.get('statistics', {})
        if stats:
            summary.append("\n流量统计:")
            summary.append(f"  总数据包数: {stats.get('total_packets', 0)}")
            
            protocols = stats.get('protocols', {})
            if protocols:
                summary.append("  协议分布:")
                for protocol, count in list(protocols.items())[:5]:
                    summary.append(f"    {protocol}: {count} 个数据包")
            
            if 'avg_packet_size' in stats:
                summary.append(f"  平均数据包大小: {stats['avg_packet_size']:.2f} 字节")
        
        # AI分析结果
        ai_analysis = result.get('ai_analysis', {})
        analysis_list = ai_analysis.get('attacks', {}).get('attacks', [])
        summary.append("\n风暴型DoS检测结果:")
        for attack in analysis_list:
            summary.append(f"  攻击类型: {attack.get('attack_type', 'N/A')}")
            summary.append(f"  置信度: {attack.get('confidence', 0)}%")
            summary.append(f"  严重程度: {attack.get('severity', 'N/A')}")
            summary.append(f"  描述: {attack.get('description', attack.get('description：', 'N/A'))}")
            summary.append(f"  建议: {attack.get('recommendations', [])}")
        
        # 攻击模式
        attack_patterns = result.get('attack_patterns', [])
        if attack_patterns:
            summary.append("\n剧毒型DoS检测结果:")
            patterns = attack_patterns[0].get('attack_patterns', [])
            for pattern in patterns:  
                # summary.append(f"  - {pattern.get('pattern_type', 'N/A')}: {pattern.get('description', 'N/A')}")
                summary.append(f"  攻击类型: {pattern.get('pattern_type', 'N/A')}")
                summary.append(f"  置信度: {pattern.get('confidence', 0)}%")
                summary.append(f"  严重程度: {pattern.get('severity', 'N/A')}")
                summary.append(f"  描述: {pattern.get('description', pattern.get('description：', 'N/A'))}")
                summary.append(f"  依据: {pattern.get('evidence', [])}")
        # 添加结尾分隔符
        summary.append("=" * 60)
        
        # 将列表拼接为字符串
        return "\n".join(summary)

if __name__ == "__main__":
    main()