#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSecAnalyzer - 硅基流动大模型接口客户端
负责与硅基流动 AI 接口交互,进行智能网络攻击检测和分析
"""

import json
import re
import time
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime

from utils import setup_logger, fix_and_parse_json


class FluidAIClient:
    """硅基流动大模型客户端"""
    
    def __init__(self, api_key: str, api_url: str = None, model: str = "fluidai-pro", timeout: int = 30, time_window: int = 5):
        """
        初始化 FluidAI 客户端
        
        Args:
            api_key: API密钥
            api_url: API接口地址
            model: 使用的模型名称
            timeout: 请求超时时间
        """
        self.api_key = api_key
        self.api_url = api_url or "https://api.fluidai.com/v1/chat/completions"
        self.model = model
        self.timeout = timeout
        self.logger = setup_logger('FluidAIClient')
        self.time_window = time_window
        
        # 请求头
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}'
        }
    
    def _make_request(self, messages: List[Dict[str, str]]) -> Optional[Dict[str, Any]]:
        """
        发送请求到 FluidAI API
        
        Args:
            messages: 消息列表
            
        Returns:
            API响应数据或None
        """
        payload = {
            'model': self.model,
            'messages': messages,
            'temperature': 0.1,  # 降低随机性,提高一致性
            'max_tokens': 2000,
            'response_format': {"type": "json_object"}
        }
        
        try:
            response = requests.post(
                self.api_url,
                headers=self.headers,
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"API请求失败: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            self.logger.error("API请求超时")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API请求异常: {e}")
            return None
    
    def analyze_network_traffic(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析网络流量数据
        
        Args:
            traffic_data: 网络流量数据
            
        Returns:
            分析结果
        """
        # 构建分析提示词
        prompt = self._build_analysis_prompt(traffic_data)
        
        messages = [
            {
                "role": "system",
                "content": """You are a professional cybersecurity forensics expert with deep knowledge of network protocols. Your task is to analyze the provided network traffic data and identify potential cybersecurity threats by distinguishing real attacks from normal network activities. Focus on patterns and quantitative indicators.
                    You need to precisely identify the following types of attacks based on concrete evidence:
                    1.  Port Scanning: Identify sequential or rapid attempts to connect to multiple ports on a single host from a single source. Exclude normal service discovery or single connection failures.
                    2.  Address Scanning: Identify attempts to connect to a specific port across a range of IP addresses within a short time frame.
                    3.  Flooding Attacks (General): Look for an abnormally high volume of traffic from one or a few sources targeting a specific host or port, exceeding normal thresholds.
                    4.  SYN Flood: A large number of SYN packets are sent to a target from various or spoofed source addresses, often without a corresponding SYN-ACK response, leading to resource exhaustion. Pay close attention to a high ratio of SYN packets to SYN-ACK packets.
                    5.  UDP Flood: A massive volume of UDP packets is sent to a target's open or closed ports. Look for a high packet rate and an unusual ratio of request to response traffic.
                    6.  ICMP Flood: An excessive volume of ICMP echo requests (ping) or other ICMP messages are sent to overwhelm the target's bandwidth.
                    7.  Anomalous Traffic Patterns: Look for deviations from baseline network behavior, such as sudden spikes in traffic volume, unusual port usage, or data transfers at odd hours, when specific attack signatures are not met.
                    8.  Other Suspicious Activities: Use this category for events that exhibit malicious intent but do not fit the above categories. Provide a low confidence score if the evidence is not conclusive.

                    Provide the analysis results in JSON format. The JSON must strictly adhere to the following structure:
                    - attack_type: The specific attack type identified. If uncertain, use "Other Suspicious Activities".
                    - confidence: A confidence score (0-100), where scores below 50 indicate low confidence due to limited or ambiguous evidence.
                    - description: A concise explanation of the observed activity.
                    - evidence: A detailed, quantitative explanation of the evidence, including specific metrics (e.g., packet counts, packet rates per second, number of unique sources/destinations) that support the conclusion.
                    - recommendations: Specific, actionable recommendations for mitigation.
                    - severity: The severity level (LOW/MEDIUM/HIGH/CRITICAL) based on the potential impact.
                    Ensure the JSON syntax is perfectly correct.
                """
            },
            {
                "role": "user",
                "content": prompt
                
            }
        ]
        analysis_result = None
        while analysis_result is None:
            response = self._make_request(messages)
            if response and 'choices' in response:
                content = response['choices'][0]['message']['content']
                analysis_result = fix_and_parse_json(content)
            
        return self._process_analysis_result(analysis_result, traffic_data)
    
    def _build_analysis_prompt(self, traffic_data: List[Dict[str, Any]]) -> str:
        """
        构建分析提示词。

        Args:
            traffic_data: 流量数据，预期为包含SliceInfo.to_dict()结果的列表。

        Returns:
            格式化的提示词。
        """
        if not traffic_data:
            return "无法分析，流量数据为空。"

        prompt = "以下是网络流量在不同时间片内的分析概览：\n\n"
        
        for slice_data in traffic_data:
            # 构建每个时间片的详细信息
            slice_prompt = (
                f"--- 时间片: {slice_data['time_slot']/self.time_window}  ---\n"
                f"  TCP 数据包总数: {slice_data['tcp_count']}\n"
                f"  UDP 数据包总数: {slice_data['udp_count']}\n"
                f"  TCP Flags 统计: SYN={slice_data['tcp_flags']['syn']}, ACK={slice_data['tcp_flags']['ack']}, RST={slice_data['tcp_flags']['rst']}\n"
            )
            prompt += slice_prompt + "\n"
            if len(slice_data['tcp_ports'])<=100 : 
                prompt += f"  TCP 端口: {slice_data['tcp_ports']}\n"
            if len(slice_data['udp_ports'])<=100 : 
                prompt += f"  UDP 端口: {slice_data['udp_ports']}\n"

            prompt += f"本时间片包含对{len(slice_data['tcp_ports'])+len(slice_data['udp_ports'])}个不同端口的访问。\n"
            
        prompt += "根据以上数据，请进行深入分析，例如：流量模式、异常行为、常见协议等。"
        
        return prompt
    
    def _process_analysis_result(self, analysis_result: Dict[str, Any], traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理AI分析结果
        
        Args:
            analysis_result: AI返回的分析结果
            traffic_data: 原始流量数据
            
        Returns:
            处理后的分析结果
        """
        result = {
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'AI_ANALYSIS',
            'model_used': self.model,
        }
        
        # 合并AI分析结果
        result['attacks'] = analysis_result 
        return result
    
    def _process_text_analysis(self, text_content: str, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理文本格式的分析结果
        
        Args:
            text_content: AI返回的文本内容
            traffic_data: 原始流量数据
            
        Returns:
            处理后的分析结果
        """
        return {
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'AI_TEXT_ANALYSIS',
            'model_used': self.model,
            'attack_type': 'UNKNOWN',
            'confidence': 50,
            'description': 'AI文本分析结果',
            'evidence': text_content,
            'recommendations': ['请人工审核分析结果'],
            'severity': 'MEDIUM',
            'traffic_summary': {
                'total_packets': traffic_data.get('total_packets', 0),
                'time_window': traffic_data.get('time_window', 60),
                'protocols': traffic_data.get('protocols', {})
            }
        }
    
    def _get_default_analysis_result(self) -> Dict[str, Any]:
        """
        获取默认分析结果（当API调用失败时）
        
        Returns:
            默认分析结果
        """
        return {
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'DEFAULT_ANALYSIS',
            'model_used': 'N/A',
            'attack_type': 'UNKNOWN',
            'confidence': 0,
            'description': 'AI分析服务不可用,请检查网络连接和API配置',
            'evidence': '无法连接到FluidAI服务',
            'recommendations': ['检查API密钥配置', '验证网络连接', '联系技术支持'],
            'severity': 'LOW',
            'error': 'API_SERVICE_UNAVAILABLE'
        }
    
    def detect_attack_patterns(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        检测攻击模式
        
        Args:
            packets: 数据包列表
            
        Returns:
            检测到的攻击模式列表
        """
        if not packets:
            return []
        
        # 构建数据包分析提示词
        prompt = self._build_packet_analysis_prompt(packets)
        
        messages = [
            {
                "role": "system",
                "content": """You are a highly specialized cybersecurity analyst with expertise in identifying legacy and low-level DDoS attacks. Your task is to analyze network packet information to detect the presence of specific, "poisonous" DDoS attacks that exploit vulnerabilities in network protocols.
                    # Target Attack Types
                    Focus your analysis on the following types of attacks:
                    * Teardrop Attack: Identify fragmented IP packets that contain overlapping, oversized, or improperly sequenced fragment offsets, causing the target system to crash or malfunction during reassembly.
                    * Ping of Death: Detect oversized ICMP echo request packets that exceed the maximum permissible size of an IP packet (65,535 bytes), leading to system crashes or buffer overflows upon reassembly.
                    * Other low-level DDoS attacks: Look for traffic patterns that indicate other forms of protocol-level abuse, such as malformed packets or unusual flag combinations designed to crash a system rather than simply flood it.

                    # Analysis Requirements

                    You will receive network packet data in a JSON or structured format. Your analysis must be based on the provided data and should consider packet size, fragmentation flags, offset values, protocol types, and source/destination information.

                    # Response Format

                    Your output must be a JSON object, strictly following this schema. If no such attacks are found, return an empty list or a list with a single entry indicating no threats detected.
                    {
                    "attack_patterns": [
                        {
                        "pattern_type": "The name of the detected attack (e.g., 'Teardrop Attack', 'Ping of Death')",
                        "severity": "Severity of the attack (LOW, MEDIUM, HIGH, CRITICAL)",
                        "confidence": "A confidence score (0-100) indicating the certainty of the detection",
                        "description": "A brief, clear description of the detected attack and its potential impact",
                        "evidence": "Specific packet details or metrics that serve as evidence (e.g., 'Packet with size 65540 bytes', 'Overlapping IP fragment offsets found')",
                        }
                    ]
                    }
                """
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
        
        response = self._make_request(messages)
        
        if response and 'choices' in response:
            try:
                content = response['choices'][0]['message']['content']
                # json_match = re.search(r'```json\n(.*?)\n```', content, re.DOTALL)
                # patterns = json.loads(json_match.group(1))
                patterns = json.loads(content)
                # 确保返回的是列表
                if isinstance(patterns, dict):
                    patterns = [patterns]
                
                return patterns
            except json.JSONDecodeError:
                self.logger.warning("无法解析攻击模式分析结果")
                return []
        
        return []
    
    def get_patterns(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        提取包特征
        
        Args:
            packets: 数据包列表
            
        Returns:
            检测到的攻击模式列表
        """
        src_ip = set()
        dst_ip = set()
        src_port = set()
        dst_port = set()
        packet_size = {'0-100':0, '100-500':0, '500-1000':0, '1000-1500':0, '1500+':0}
        
        for packet in packets:
            src_ip.add(packet['src_ip'])
            dst_ip.add(packet['dst_ip'])
            src_port.add(packet['src_port'])
            dst_port.add(packet['dst_port'])
            packet_size['0-100' if packet['packet_size']<=100 else
                        '100-500' if packet['packet_size']<=500 else
                        '500-1000' if packet['packet_size']<=1000 else
                        '1000-1500' if packet['packet_size']<=1500 else
                        '1500+'] += 1
        return {
            'src_ip':sorted(list(src_ip)),
            'dst_ip':sorted(list(dst_ip)),
            'src_port':sorted(list(src_port)),
            'dst_port':sorted(list(dst_port)),
            'packet_size':packet_size
        }
    
    def test_connection(self) -> bool:
        """
        测试与FluidAI API的连接
        
        Returns:
            连接是否成功
        """
        test_messages = [
            {
                "role": "user",
                "content": "请回复'连接测试成功'"
            }
        ]
        
        response = self._make_request(test_messages)
        
        if response and 'choices' in response:
            content = response['choices'][0]['message']['content']
            self.logger.info(f"FluidAI API连接测试成功: {content}")
            return True
        else:
            self.logger.error("FluidAI API连接测试失败")
            return False

if __name__ == "__main__":
    # 模拟网络流量数据
    traffic_data = {
        "total_packets": 1000,
        "time_window": 60,
        "timestamp": datetime.now().isoformat(),
        "protocols": {
            "TCP": 700,
            "UDP": 300
        },
        "top_sources": {
            "192.168.1.1": 200,
            "192.168.1.2": 150
        },
        "top_destinations": {
            "10.0.0.1": 300,
            "10.0.0.2": 250
        },
        "avg_packet_size": 500,
        "min_packet_size": 64,
        "max_packet_size": 1500
    }

    # 从 config.yaml 中读取配置
    import yaml
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    
    # 初始化 FluidAIClient
    client = FluidAIClient(
        api_key=config["fluidai"]["api_key"],
        api_url=config["fluidai"]["api_url"],
        model=config["fluidai"]["model"],
        timeout=config["fluidai"]["timeout"]
    )

    # 调用 analyze_network_traffic
    result = client.analyze_network_traffic(traffic_data)
    print("分析结果:", result)
