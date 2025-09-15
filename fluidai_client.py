#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSecAnalyzer - 硅基流动大模型接口客户端
负责与硅基流动 AI 接口交互，进行智能网络攻击检测和分析
"""

import json
import time
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime

from utils import setup_logger, Constants, create_attack_report


class FluidAIClient:
    """硅基流动大模型客户端"""
    
    def __init__(self, api_key: str, api_url: str = None, model: str = "fluidai-pro", timeout: int = 30):
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
            'temperature': 0.1,  # 降低随机性，提高一致性
            'max_tokens': 2000
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
                "content": """你是一个专业的网络安全分析专家，擅长识别各种网络攻击模式。
                请仔细分析提供的网络流量数据，识别潜在的网络安全威胁。
                你需要识别以下类型的攻击：
                1. 端口扫描 (Port Scanning)
                2. 地址扫描 (Address Scanning) 
                3. 泛洪攻击 (Flooding Attacks)
                4. SYN泛洪 (SYN Flood)
                5. UDP泛洪 (UDP Flood)
                6. ICMP泛洪 (ICMP Flood)
                7. 异常流量模式
                8. 其他可疑行为
                
                请以JSON格式返回分析结果，包含：
                - attack_type: 攻击类型
                - confidence: 置信度 (0-100)
                - description: 攻击描述
                - evidence: 证据说明
                - recommendations: 防护建议
                - severity: 严重程度 (LOW/MEDIUM/HIGH/CRITICAL)
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
                # 尝试解析JSON响应
                analysis_result = json.loads(content)
                return self._process_analysis_result(analysis_result, traffic_data)
            except json.JSONDecodeError:
                # 如果JSON解析失败，返回文本分析结果
                return self._process_text_analysis(response['choices'][0]['message']['content'], traffic_data)
        
        return self._get_default_analysis_result()
    
    def _build_analysis_prompt(self, traffic_data: Dict[str, Any]) -> str:
        """
        构建分析提示词
        
        Args:
            traffic_data: 流量数据
            
        Returns:
            格式化的提示词
        """
        prompt = f"""
请分析以下网络流量数据，识别潜在的安全威胁：

## 流量统计信息
- 总数据包数: {traffic_data.get('total_packets', 0)}
- 分析时间窗口: {traffic_data.get('time_window', 60)} 秒
- 分析时间: {traffic_data.get('timestamp', datetime.now().isoformat())}

## 协议分布
"""
        
        protocols = traffic_data.get('protocols', {})
        for protocol, count in protocols.items():
            prompt += f"- {protocol}: {count} 个数据包\n"
        
        prompt += "\n## 主要源IP地址\n"
        sources = traffic_data.get('top_sources', {})
        for ip, count in list(sources.items())[:5]:
            prompt += f"- {ip}: {count} 个数据包\n"
        
        prompt += "\n## 主要目标IP地址\n"
        destinations = traffic_data.get('top_destinations', {})
        for ip, count in list(destinations.items())[:5]:
            prompt += f"- {ip}: {count} 个数据包\n"
        
        if 'avg_packet_size' in traffic_data:
            prompt += f"\n## 数据包大小统计\n"
            prompt += f"- 平均大小: {traffic_data['avg_packet_size']:.2f} 字节\n"
            prompt += f"- 最小大小: {traffic_data['min_packet_size']} 字节\n"
            prompt += f"- 最大大小: {traffic_data['max_packet_size']} 字节\n"
        
        # 添加异常检测提示
        prompt += "\n## 异常检测提示\n"
        prompt += "请特别关注以下异常模式：\n"
        prompt += "1. 单一IP对多个端口的大量连接尝试（端口扫描）\n"
        prompt += "2. 单一IP对多个目标IP的连接尝试（地址扫描）\n"
        prompt += "3. 短时间内大量相同类型的数据包（泛洪攻击）\n"
        prompt += "4. 异常的数据包大小或协议分布\n"
        prompt += "5. 非标准端口的大量流量\n"
        
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
            'traffic_summary': {
                'total_packets': traffic_data.get('total_packets', 0),
                'time_window': traffic_data.get('time_window', 60),
                'protocols': traffic_data.get('protocols', {})
            }
        }
        
        # 合并AI分析结果
        result.update(analysis_result)
        
        # 添加默认值
        result.setdefault('attack_type', 'NORMAL_TRAFFIC')
        result.setdefault('confidence', 50)
        result.setdefault('description', '网络流量正常，未检测到明显攻击')
        result.setdefault('evidence', '流量模式符合正常网络行为')
        result.setdefault('recommendations', ['继续监控网络流量', '定期更新安全策略'])
        result.setdefault('severity', 'LOW')
        
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
            'description': 'AI分析服务不可用，请检查网络连接和API配置',
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
                "content": """你是一个专业的网络安全分析专家，专门分析数据包级别的攻击模式。
                请分析提供的数据包序列，识别可能的攻击行为。
                
                重点关注以下攻击模式：
                1. 端口扫描：短时间内对多个端口进行连接尝试
                2. 地址扫描：短时间内对多个IP地址进行连接尝试
                3. SYN泛洪：大量SYN包，无对应ACK包
                4. UDP泛洪：大量UDP包到同一目标
                5. ICMP泛洪：大量ICMP包
                6. 异常连接模式：非正常的连接序列
                
                请返回JSON格式的分析结果数组，每个攻击模式包含：
                - pattern_type: 攻击模式类型
                - confidence: 置信度
                - affected_ips: 受影响的IP地址
                - description: 详细描述
                - recommendations: 防护建议
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
                patterns = json.loads(content)
                
                # 确保返回的是列表
                if isinstance(patterns, dict):
                    patterns = [patterns]
                
                return patterns
            except json.JSONDecodeError:
                self.logger.warning("无法解析攻击模式分析结果")
                return []
        
        return []
    
    def _build_packet_analysis_prompt(self, packets: List[Dict[str, Any]]) -> str:
        """
        构建数据包分析提示词
        
        Args:
            packets: 数据包列表
            
        Returns:
            格式化的提示词
        """
        prompt = f"请分析以下 {len(packets)} 个数据包，识别攻击模式：\n\n"
        
        # 只显示前50个数据包，避免提示词过长
        sample_packets = packets[:50]
        
        for i, packet in enumerate(sample_packets):
            prompt += f"数据包 {i+1}:\n"
            prompt += f"  时间: {packet.get('timestamp', 'N/A')}\n"
            prompt += f"  协议: {packet.get('protocol', 'N/A')}\n"
            prompt += f"  源: {packet.get('src_ip', 'N/A')}:{packet.get('src_port', 'N/A')}\n"
            prompt += f"  目标: {packet.get('dst_ip', 'N/A')}:{packet.get('dst_port', 'N/A')}\n"
            prompt += f"  大小: {packet.get('packet_size', 'N/A')} 字节\n\n"
        
        if len(packets) > 50:
            prompt += f"... 还有 {len(packets) - 50} 个数据包\n\n"
        
        prompt += "请分析这些数据包序列，识别可能的攻击模式。"
        
        return prompt
    
    def get_attack_recommendations(self, attack_type: str, severity: str) -> List[str]:
        """
        获取攻击防护建议
        
        Args:
            attack_type: 攻击类型
            severity: 严重程度
            
        Returns:
            防护建议列表
        """
        recommendations = {
            'PORT_SCAN': [
                '配置防火墙规则，限制来自可疑IP的连接',
                '启用入侵检测系统(IDS)',
                '监控网络连接日志',
                '考虑使用蜜罐技术'
            ],
            'ADDRESS_SCAN': [
                '实施网络分段和访问控制',
                '启用网络监控和告警',
                '配置路由器访问控制列表(ACL)',
                '使用网络扫描检测工具'
            ],
            'FLOODING': [
                '配置流量限制和速率限制',
                '启用DDoS防护服务',
                '调整服务器连接超时设置',
                '使用负载均衡器分散流量'
            ],
            'SYN_FLOOD': [
                '启用SYN Cookie保护',
                '调整TCP连接参数',
                '使用防火墙SYN Flood防护',
                '配置反向代理'
            ],
            'UDP_FLOOD': [
                '限制UDP连接速率',
                '过滤不必要的UDP服务',
                '启用UDP Flood防护',
                '监控UDP流量模式'
            ],
            'ICMP_FLOOD': [
                '限制ICMP消息速率',
                '禁用不必要的ICMP响应',
                '配置ICMP Flood防护',
                '监控ICMP流量'
            ]
        }
        
        base_recommendations = recommendations.get(attack_type, [
            '启用网络监控',
            '检查防火墙配置',
            '更新安全策略',
            '联系安全团队'
        ])
        
        # 根据严重程度添加额外建议
        if severity in ['HIGH', 'CRITICAL']:
            base_recommendations.insert(0, '立即启动应急响应流程')
            base_recommendations.append('通知相关安全人员')
        
        return base_recommendations
    
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


class MockFluidAIClient(FluidAIClient):
    """模拟FluidAI客户端，用于测试和演示"""
    
    def __init__(self, api_key: str = "mock_key", **kwargs):
        super().__init__(api_key, **kwargs)
        self.logger.info("使用模拟FluidAI客户端")
    
    def _make_request(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        模拟API请求
        
        Args:
            messages: 消息列表
            
        Returns:
            模拟的API响应
        """
        # 模拟网络延迟
        time.sleep(0.5)
        
        # 根据消息内容返回不同的模拟响应
        user_content = messages[-1]['content'] if messages else ""
        
        if '端口扫描' in user_content or 'PORT_SCAN' in user_content:
            return {
                'choices': [{
                    'message': {
                        'content': json.dumps({
                            'attack_type': 'PORT_SCAN',
                            'confidence': 85,
                            'description': '检测到疑似端口扫描行为，单一IP在短时间内尝试连接多个端口',
                            'evidence': '发现来自192.168.1.100的IP在60秒内尝试连接超过10个不同端口',
                            'recommendations': [
                                '配置防火墙规则限制该IP访问',
                                '启用端口扫描检测',
                                '监控后续连接尝试'
                            ],
                            'severity': 'MEDIUM'
                        })
                    }
                }]
            }
        elif '泛洪' in user_content or 'FLOOD' in user_content:
            return {
                'choices': [{
                    'message': {
                        'content': json.dumps({
                            'attack_type': 'FLOODING',
                            'confidence': 92,
                            'description': '检测到疑似泛洪攻击，短时间内大量数据包涌入',
                            'evidence': '检测到来自多个IP的大量UDP数据包，总流量超过正常水平10倍',
                            'recommendations': [
                                '启用DDoS防护',
                                '限制连接速率',
                                '联系网络管理员'
                            ],
                            'severity': 'HIGH'
                        })
                    }
                }]
            }
        else:
            return {
                'choices': [{
                    'message': {
                        'content': json.dumps({
                            'attack_type': 'NORMAL_TRAFFIC',
                            'confidence': 75,
                            'description': '网络流量正常，未检测到明显攻击行为',
                            'evidence': '流量模式符合正常网络使用模式',
                            'recommendations': [
                                '继续监控网络流量',
                                '定期检查安全日志'
                            ],
                            'severity': 'LOW'
                        })
                    }
                }]
            }


if __name__ == "__main__":
    # 测试代码
    client = MockFluidAIClient()
    
    # 测试连接
    if client.test_connection():
        print("FluidAI客户端测试成功")
        
        # 测试流量分析
        test_traffic = {
            'total_packets': 1000,
            'time_window': 60,
            'protocols': {'TCP': 800, 'UDP': 150, 'ICMP': 50},
            'top_sources': {'192.168.1.100': 500, '192.168.1.101': 300},
            'top_destinations': {'192.168.1.1': 400, '8.8.8.8': 200}
        }
        
        result = client.analyze_network_traffic(test_traffic)
        print("分析结果:", json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("FluidAI客户端测试失败")