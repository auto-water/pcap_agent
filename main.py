#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSecAnalyzer - 主入口文件
智能网络安全分析工具，集成 PyPCAP 网络抓包和硅基流动 AI 分析
"""

import os
import sys
import time
import signal
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
        
        # 设置信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.is_running = False
        self.analysis_results = []
        
        if not self.silent_mode:
            self.logger.info("NetSecAnalyzer 初始化完成")
    
    def _signal_handler(self, signum, frame):
        """信号处理器"""
        self.logger.info(f"接收到信号 {signum}，正在安全退出...")
        self.stop()
        sys.exit(0)
    
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
        if use_ai and self.config.get('analysis', {}).get('enable_ai_analysis', True):
            if not self.fluidai_client:
                self._init_fluidai_client(use_mock=True)
            
            if self.fluidai_client:
                try:
                    # 分析流量统计
                    ai_result = self.fluidai_client.analyze_network_traffic(stats.get('statistics', {}))
                    result['ai_analysis'] = ai_result
                    
                    # 分析数据包模式
                    packet_dicts = [p.to_dict() for p in packets[:100]]  # 限制数量避免API限制
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
    
    def print_analysis_summary(self, result: Dict[str, Any]):
        """
        打印分析结果摘要
        
        Args:
            result: 分析结果
        """
        print("\n" + "="*60)
        print("网络流量分析结果摘要")
        print("="*60)
        
        if 'file_path' in result:
            print(f"分析文件: {result['file_path']}")
        
        if 'capture_time' in result:
            print(f"抓包时间: {result['capture_time']}")
        
        print(f"分析时间: {result.get('analysis_time', result.get('capture_time', 'N/A'))}")
        
        stats = result.get('statistics', {})
        if stats:
            print(f"\n流量统计:")
            print(f"  总数据包数: {stats.get('total_packets', 0)}")
            
            protocols = stats.get('protocols', {})
            if protocols:
                print(f"  协议分布:")
                for protocol, count in list(protocols.items())[:5]:
                    print(f"    {protocol}: {count} 个数据包")
            
            if 'avg_packet_size' in stats:
                print(f"  平均数据包大小: {stats['avg_packet_size']:.2f} 字节")
            
            # 攻击统计信息
            attack_summary = stats.get('attack_summary', {})
            if attack_summary and attack_summary.get('total_attacks', 0) > 0:
                print(f"\n攻击检测统计:")
                print(f"  总攻击事件: {attack_summary.get('total_attacks', 0)}")
                print(f"  端口扫描: {attack_summary.get('port_scans', 0)}")
                print(f"  地址扫描: {attack_summary.get('address_scans', 0)}")
                print(f"  泛洪攻击: {attack_summary.get('flood_attacks', 0)}")
        
        # AI分析结果
        ai_analysis = result.get('ai_analysis', {})
        analysis_list = ai_analysis['attacks']
        for attack in analysis_list:
            print(f"\nAI检测到的攻击:")
            print(f"  攻击类型: {attack.get('attack_type', 'N/A')}")
            print(f"  置信度: {attack.get('confidence', 0)}%")
            print(f"  严重程度: {attack.get('severity', 'N/A')}")
            print(f"  描述: {attack.get('description', 'N/A')}")
            print(f"  建议: {attack.get('recommendations', [])}")
        
        # 攻击模式
        attack_patterns = result.get('attack_patterns', [])
        if attack_patterns:
            print(f"\n检测到的攻击模式:")
            for pattern in attack_patterns[:3]:  # 显示前3个模式
                print(f"  - {pattern.get('pattern_type', 'N/A')}: {pattern.get('description', 'N/A')}")
        
        print("="*60)


def create_parser() -> argparse.ArgumentParser:
    """创建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        description='NetSecAnalyzer - 智能网络安全分析工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 分析PCAP文件
  python main.py -f capture.pcap
  
  # 实时抓包分析（30秒）
  python main.py -r -d 30
  
  # 实时抓包分析，指定网络接口
  python main.py -r -i eth0
  
  # 分析PCAP文件并保存结果
  python main.py -f capture.pcap -o result.json
  
  # 使用真实AI API（需要配置API密钥）
  python main.py -f capture.pcap --real-ai
        """
    )
    
    # 主要操作模式
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', type=str, metavar='PCAP_FILE',
                      help='分析指定的PCAP文件')
    
    # 输出选项
    parser.add_argument('-o', '--output', type=str, metavar='OUTPUT_FILE',
                       help='保存分析结果到指定文件')
    # 配置选项
    parser.add_argument('-c', '--config', type=str, metavar='CONFIG_FILE',
                       help='指定配置文件路径')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='启用详细输出')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='静默模式，仅输出错误信息')
    parser.add_argument('--simple', '-s', action='store_true',
                       help='简洁模式，只显示进度条和最终结果')
    
    return parser


def main():
    """主函数"""
    # 解析命令行参数
    parser = create_parser()
    args = parser.parse_args()
    
    # 设置日志级别和静默模式
    if args.quiet:
        log_level = 'ERROR'
        silent_mode = True
    elif args.simple:
        log_level = 'WARNING'
        silent_mode = True
    elif args.verbose:
        log_level = 'DEBUG'
        silent_mode = False
    else:
        log_level = 'INFO'
        silent_mode = False
    
    # 只在非静默模式下打印横幅
    if not silent_mode:
        print_banner()
    
    # 初始化分析器
    analyzer = NetSecAnalyzer(args.config, silent_mode=silent_mode)
    analyzer.logger.setLevel(log_level)
    
    try:
        result = {}
        
        if args.file:
            # 文件分析模式
            analyzer._init_fluidai_client()
            result = analyzer.analyze_pcap_file(
                file_path=args.file,
                output_file=args.output
            )
        # 打印结果摘要
        if result:
            analyzer.print_analysis_summary(result)
            
            # 保存结果（如果未指定输出文件）
            if not args.output and result:
                output_file = save_analysis_result([result])
                print(f"\n分析结果已自动保存到: {output_file}")
        
        print("\n分析完成！")
    
    except KeyboardInterrupt:
        print("\n用户中断操作")
        analyzer.stop()
    except Exception as e:
        print(f"\n发生错误: {e}")
        analyzer.logger.error(f"程序异常: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()