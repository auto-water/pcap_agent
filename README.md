# NetSecAnalyzer - 智能网络安全分析工具

NetSecAnalyzer 是一个基于 Python 的智能网络安全分析工具，集成了 PyPCAP 网络抓包技术和硅基流动（FluidAI）大模型，能够实时监控网络流量并智能识别各种网络攻击模式。

## 🌟 核心功能

### 网络抓包与分析模块
- **实时抓包**: 使用 PyPCAP 库实现网络接口实时抓包功能
- **文件分析**: 支持分析本地的 `.pcap` 或 `.pcapng` 文件
- **数据解析**: 自动解析数据包，提取关键信息：
  - 源/目的 IP 地址和端口
  - 协议类型 (TCP, UDP, ICMP)
  - 数据包大小和时间戳
  - 协议头部信息

### 智能攻击检测
- **端口扫描检测**: 识别短时间内对多个端口的连接尝试
- **地址扫描检测**: 识别短时间内对多个IP地址的连接尝试
- **泛洪攻击检测**: 检测SYN泛洪、UDP泛洪、ICMP泛洪等攻击
- **异常流量检测**: 识别异常的数据包大小和非标准协议行为
- **AI智能分析**: 集成硅基流动大模型进行深度威胁分析

### 智能体（Agent）设计
- **命令行接口**: 友好的命令行操作界面
- **实时监控**: 支持实时抓包分析和本地文件分析
- **结果输出**: 智能化的分析结果展示和报告生成
- **日志记录**: 完整的分析过程日志记录

## 🛠️ 技术栈

- **主语言**: Python 3.7+
- **网络库**: PyPCAP (pcapy-ng, scapy)
- **AI接口**: 硅基流动 (FluidAI) 大模型
- **数据处理**: pandas, numpy
- **日志系统**: colorlog
- **依赖管理**: requirements.txt

## 📦 安装

### 环境要求
- Python 3.7 或更高版本
- Windows/Linux/macOS 操作系统
- 管理员权限（用于网络抓包）

### 安装步骤

1. **克隆项目**
```bash
git clone <repository-url>
cd pcap_agent
```

2. **自动安装依赖**（推荐）
```bash
python install_dependencies.py
```

3. **手动安装依赖**（备选）
```bash
pip install -r requirements.txt
```

4. **配置API密钥**（可选）
```bash
# 编辑配置文件或设置环境变量
export FLUIDAI_API_KEY="your_api_key_here"
```

### 安装问题解决

如果在Windows上遇到 `pcapy-ng` 安装失败的问题（这是常见问题），请：

1. **使用自动安装脚本**（推荐）
```bash
python install_dependencies.py
```

2. **手动安装替代库**
```bash
# 安装基础依赖
pip install requests pandas numpy colorlog pyyaml python-dateutil tqdm

# 安装scapy（用于PCAP文件分析）
pip install scapy

# 如果需要实时抓包，安装以下之一：
# Windows: 先安装 Npcap 或 WinPcap，然后安装 pypcap
# pip install pypcap

# Linux/macOS: 安装 pcapy-ng
# pip install pcapy-ng
```

3. **验证安装**
```bash
python test_installation.py
```

## 🚀 使用方法

### 基本用法

#### 1. 分析PCAP文件
```bash
# 分析指定的PCAP文件
python main.py -f capture.pcap

# 分析文件并保存结果
python main.py -f capture.pcap -o result.json

# 使用真实AI API分析
python main.py -f capture.pcap --real-ai
```

#### 2. 实时网络抓包
```bash
# 实时抓包分析（按Ctrl+C停止）
python main.py -r

# 抓包30秒后自动停止
python main.py -r -d 30

# 指定网络接口抓包
python main.py -r -i eth0

# 设置抓包过滤器
python main.py -r --filter "tcp port 80"
```

### 高级选项

#### 命令行参数详解

| 参数 | 说明 | 示例 |
|------|------|------|
| `-f, --file` | 分析指定的PCAP文件 | `python main.py -f capture.pcap` |
| `-r, --realtime` | 进行实时网络抓包 | `python main.py -r` |
| `-i, --interface` | 指定网络接口 | `python main.py -r -i eth0` |
| `-d, --duration` | 抓包持续时间（秒） | `python main.py -r -d 60` |
| `--filter` | 设置抓包过滤器 | `python main.py -r --filter "tcp port 80"` |
| `-o, --output` | 保存分析结果 | `python main.py -f file.pcap -o result.json` |
| `--no-ai` | 禁用AI分析 | `python main.py -f file.pcap --no-ai` |
| `--real-ai` | 使用真实FluidAI API | `python main.py -f file.pcap --real-ai` |
| `-v, --verbose` | 详细输出模式 | `python main.py -f file.pcap -v` |
| `-q, --quiet` | 静默模式 | `python main.py -f file.pcap -q` |

### 配置文件

创建 `config.yaml` 文件进行高级配置：

```yaml
# FluidAI 配置
fluidai:
  api_url: "https://api.fluidai.com/v1/chat/completions"
  api_key: "your_api_key_here"
  model: "fluidai-pro"
  timeout: 30

# 分析配置
analysis:
  enable_realtime: true
  packet_limit: 10000
  time_window: 60
  enable_ai_analysis: true

# 日志配置
logging:
  level: "INFO"
  file_enabled: true
  console_enabled: true
```

## 📊 输出示例

### 分析结果摘要
```
============================================================
网络流量分析结果摘要
============================================================
分析文件: capture.pcap
分析时间: 2024-01-15T10:30:00.123456
流量统计:
  总数据包数: 15420
  协议分布:
    TCP: 12336 个数据包
    UDP: 2580 个数据包
    ICMP: 504 个数据包
  平均数据包大小: 892.34 字节

AI分析结果:
  攻击类型: PORT_SCAN
  置信度: 85%
  严重程度: MEDIUM
  描述: 检测到疑似端口扫描行为，单一IP在短时间内尝试连接多个端口
  建议:
    - 配置防火墙规则限制该IP访问
    - 启用端口扫描检测
    - 监控后续连接尝试
============================================================
```

### 攻击检测示例
```
[WARNING] 检测到端口扫描: {'attack_type': 'PORT_SCAN', 'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.1', 'packet_count': 15, 'threshold': 10}
[WARNING] 检测到泛洪攻击: {'attack_type': 'FLOODING', 'source_ip': '10.0.0.5', 'dest_ip': '192.168.1.50', 'packet_count': 250, 'threshold': 100}
```

## 🔧 项目结构

```
pcap_agent/
├── main.py              # 主入口文件
├── pcap_analyzer.py     # 网络抓包与分析模块
├── fluidai_client.py    # 硅基流动AI接口客户端
├── utils.py             # 工具函数和常量
├── requirements.txt     # 依赖包列表
├── README.md           # 项目说明文档
└── config.yaml         # 配置文件（可选）
```

## 🛡️ 攻击检测能力

### 支持的攻击类型

| 攻击类型 | 检测方法 | 阈值配置 |
|----------|----------|----------|
| 端口扫描 | 统计单IP对多端口连接 | 默认10个端口/60秒 |
| 地址扫描 | 统计单IP对多目标连接 | 默认50个地址/60秒 |
| SYN泛洪 | 检测大量SYN包 | 默认100个包/10秒 |
| UDP泛洪 | 检测大量UDP包 | 默认100个包/10秒 |
| ICMP泛洪 | 检测大量ICMP包 | 默认100个包/10秒 |
| 异常流量 | AI智能分析 | 动态阈值 |

### 检测算法

1. **规则引擎检测**: 基于预定义规则和阈值的快速检测
2. **AI智能分析**: 使用硅基流动大模型进行深度模式识别
3. **统计分析**: 基于流量统计特征的异常检测
4. **实时监控**: 持续监控和实时告警

## 🔍 故障排除

### 常见问题

#### 1. pcapy-ng 安装失败（Windows）
**问题**: `AttributeError: module 'distutils.sysconfig' has no attribute '_init_posix'`

**解决方案**:
```bash
# 使用自动安装脚本（推荐）
python install_dependencies.py

# 或者手动安装替代库
pip install scapy  # 基础功能
pip install pcapkit  # 如果可用
```

#### 2. 权限不足
```bash
# Windows: 以管理员身份运行
# Linux/macOS: 使用sudo
sudo python main.py -r
```

#### 3. 网络接口不可用
```bash
# 查看可用网络接口（如果安装了pcapy）
python -c "import pcapy; print(pcapy.findalldevs())"

# 或者使用系统命令
# Windows: ipconfig
# Linux: ip addr show
# macOS: ifconfig
```

#### 4. 依赖库安装失败
```bash
# 安装系统依赖（Ubuntu/Debian）
sudo apt-get install libpcap-dev

# 安装系统依赖（CentOS/RHEL）
sudo yum install libpcap-devel

# Windows: 安装 WinPcap 或 Npcap
# 下载地址: https://npcap.com/download/
```

#### 5. API连接失败
```bash
# 检查网络连接
ping api.fluidai.com

# 验证API密钥
python -c "from fluidai_client import FluidAIClient; client = FluidAIClient('your_key'); print(client.test_connection())"

# 使用模拟客户端
python main.py -f file.pcap --no-ai
```

#### 6. 配置文件问题
```bash
# 如果配置文件加载失败，程序会使用默认配置
# 可以手动创建 config.yaml 文件
cp config.yaml.example config.yaml
```

### 调试模式

启用详细日志输出：
```bash
python main.py -f capture.pcap -v
```

查看日志文件：
```bash
tail -f netsec_analyzer_20240115.log
```

## 🤝 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [PyPCAP](https://github.com/CoreSecurity/pcapy) - 网络抓包库
- [Scapy](https://scapy.net/) - 数据包操作库
- [硅基流动](https://fluidai.com/) - AI大模型服务
- [ColorLog](https://github.com/borntyping/python-colorlog) - 彩色日志库

## 📞 支持

如果您遇到问题或有任何建议，请：

1. 查看 [Issues](https://github.com/your-repo/issues) 页面
2. 创建新的 Issue
3. 联系维护者

---

**注意**: 本工具仅用于合法的网络安全分析和研究目的。请确保在授权网络环境中使用，并遵守相关法律法规。