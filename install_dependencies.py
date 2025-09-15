#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSecAnalyzer - 依赖安装脚本
自动检测和安装项目所需的依赖库
"""

import sys
import subprocess
import platform
import os
from typing import List, Tuple


def run_command(command: str, description: str) -> Tuple[bool, str]:
    """
    运行命令并返回结果
    
    Args:
        command: 要执行的命令
        description: 命令描述
        
    Returns:
        (是否成功, 输出信息)
    """
    print(f"正在{description}...")
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=300
        )
        
        if result.returncode == 0:
            print(f"✓ {description}成功")
            return True, result.stdout
        else:
            print(f"✗ {description}失败: {result.stderr}")
            return False, result.stderr
            
    except subprocess.TimeoutExpired:
        print(f"✗ {description}超时")
        return False, "命令执行超时"
    except Exception as e:
        print(f"✗ {description}异常: {e}")
        return False, str(e)


def check_python_version():
    """检查Python版本"""
    version = sys.version_info
    print(f"Python版本: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print("❌ 错误: 需要Python 3.7或更高版本")
        return False
    
    print("✓ Python版本符合要求")
    return True


def install_basic_dependencies():
    """安装基础依赖"""
    basic_deps = [
        "requests>=2.31.0",
        "urllib3>=2.1.0", 
        "pandas>=2.1.4",
        "numpy>=1.24.3",
        "colorlog>=6.8.0",
        "pyyaml>=6.0.1",
        "python-dateutil>=2.8.2",
        "tqdm>=4.66.1"
    ]
    
    print("\n=== 安装基础依赖 ===")
    for dep in basic_deps:
        success, _ = run_command(f"pip install {dep}", f"安装 {dep}")
        if not success:
            print(f"⚠ 警告: {dep} 安装失败，继续安装其他依赖")


def install_pcap_libraries():
    """安装PCAP相关库"""
    print("\n=== 安装PCAP库 ===")
    
    # 首先尝试安装 pcapkit（推荐）
    success, _ = run_command("pip install pcapkit>=1.0.2", "安装 pcapkit")
    if success:
        print("✓ pcapkit 安装成功，这是推荐的PCAP库")
        return True
    
    # 尝试安装 scapy
    success, _ = run_command("pip install scapy>=2.5.0", "安装 scapy")
    if success:
        print("✓ scapy 安装成功")
    else:
        print("⚠ scapy 安装失败")
    
    # 根据操作系统尝试其他库
    system = platform.system().lower()
    
    if system == "windows":
        print("\nWindows系统检测到，尝试安装Windows兼容的PCAP库...")
        
        # 提示用户安装 WinPcap 或 Npcap
        print("⚠ 注意: 在Windows上，您可能需要安装 WinPcap 或 Npcap")
        print("  下载地址:")
        print("  - Npcap: https://npcap.com/download/")
        print("  - WinPcap: https://www.winpcap.org/install/default.htm")
        
        # 尝试安装 pypcap
        success, _ = run_command("pip install pypcap", "安装 pypcap")
        if success:
            print("✓ pypcap 安装成功")
            return True
        
        # 尝试安装 pcapy-ng
        success, _ = run_command("pip install pcapy-ng", "安装 pcapy-ng")
        if success:
            print("✓ pcapy-ng 安装成功")
            return True
    
    elif system in ["linux", "darwin"]:
        print(f"\n{system.title()}系统检测到...")
        
        # 尝试安装 pcapy-ng
        success, _ = run_command("pip install pcapy-ng", "安装 pcapy-ng")
        if success:
            print("✓ pcapy-ng 安装成功")
            return True
        
        # 尝试安装 pypcap
        success, _ = run_command("pip install pypcap", "安装 pypcap")
        if success:
            print("✓ pypcap 安装成功")
            return True
    
    print("⚠ 警告: 所有PCAP库安装失败")
    print("  程序仍然可以运行，但实时抓包功能将不可用")
    print("  您可以手动安装以下库之一:")
    print("    pip install pcapkit    # 推荐")
    print("    pip install scapy      # 基础功能")
    print("    pip install pcapy-ng   # 传统库")
    
    return False


def test_imports():
    """测试导入"""
    print("\n=== 测试库导入 ===")
    
    test_cases = [
        ("requests", "HTTP请求库"),
        ("pandas", "数据处理库"),
        ("numpy", "数值计算库"),
        ("colorlog", "彩色日志库"),
        ("yaml", "YAML配置库"),
        ("scapy", "数据包处理库"),
        ("pcapkit", "PCAP处理库"),
        ("pcapy", "PCAP处理库"),
        ("pcap", "PCAP处理库")
    ]
    
    available_libs = []
    
    for lib, description in test_cases:
        try:
            __import__(lib)
            print(f"✓ {lib} - {description}")
            available_libs.append(lib)
        except ImportError:
            print(f"✗ {lib} - {description} (未安装)")
    
    # 检查PCAP库可用性
    pcap_libs = [lib for lib in available_libs if lib in ['scapy', 'pcapkit', 'pcapy', 'pcap']]
    
    if pcap_libs:
        print(f"\n✓ 可用的PCAP库: {', '.join(pcap_libs)}")
        print("  实时抓包功能可用")
    else:
        print("\n⚠ 没有可用的PCAP库")
        print("  实时抓包功能不可用，但可以分析PCAP文件")
    
    return available_libs


def create_test_script():
    """创建测试脚本"""
    test_script = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSecAnalyzer 测试脚本
"""

def test_imports():
    """测试所有导入"""
    print("测试NetSecAnalyzer导入...")
    
    try:
        from utils import setup_logger, print_banner
        print("✓ utils 模块导入成功")
    except Exception as e:
        print(f"✗ utils 模块导入失败: {e}")
        return False
    
    try:
        from pcap_analyzer import PCAPAnalyzer
        print("✓ pcap_analyzer 模块导入成功")
    except Exception as e:
        print(f"✗ pcap_analyzer 模块导入失败: {e}")
        return False
    
    try:
        from fluidai_client import FluidAIClient, MockFluidAIClient
        print("✓ fluidai_client 模块导入成功")
    except Exception as e:
        print(f"✗ fluidai_client 模块导入失败: {e}")
        return False
    
    try:
        from main import NetSecAnalyzer
        print("✓ main 模块导入成功")
    except Exception as e:
        print(f"✗ main 模块导入失败: {e}")
        return False
    
    print("\\n所有模块导入测试通过！")
    return True

def test_basic_functionality():
    """测试基本功能"""
    print("\\n测试基本功能...")
    
    try:
        from utils import setup_logger, print_banner
        from pcap_analyzer import PCAPAnalyzer
        from fluidai_client import MockFluidAIClient
        
        # 测试日志
        logger = setup_logger('test')
        logger.info("测试日志功能")
        
        # 测试分析器
        analyzer = PCAPAnalyzer()
        
        # 测试AI客户端
        ai_client = MockFluidAIClient()
        
        print("✓ 基本功能测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 基本功能测试失败: {e}")
        return False

if __name__ == "__main__":
    print("NetSecAnalyzer 测试")
    print("=" * 40)
    
    if test_imports() and test_basic_functionality():
        print("\\n🎉 所有测试通过！NetSecAnalyzer 已准备就绪")
        print("\\n使用方法:")
        print("  python main.py -f your_file.pcap  # 分析PCAP文件")
        print("  python main.py -r                 # 实时抓包")
    else:
        print("\\n❌ 测试失败，请检查依赖安装")
'''
    
    with open('test_installation.py', 'w', encoding='utf-8') as f:
        f.write(test_script)
    
    print("✓ 测试脚本已创建: test_installation.py")


def main():
    """主函数"""
    print("NetSecAnalyzer 依赖安装脚本")
    print("=" * 50)
    
    # 检查Python版本
    if not check_python_version():
        sys.exit(1)
    
    # 安装基础依赖
    install_basic_dependencies()
    
    # 安装PCAP库
    pcap_success = install_pcap_libraries()
    
    # 测试导入
    available_libs = test_imports()
    
    # 创建测试脚本
    create_test_script()
    
    # 总结
    print("\n" + "=" * 50)
    print("安装完成总结:")
    print(f"- Python版本: {sys.version_info.major}.{sys.version_info.minor}")
    print(f"- 可用库数量: {len(available_libs)}")
    print(f"- PCAP功能: {'可用' if pcap_success else '不可用'}")
    
    if pcap_success:
        print("\n🎉 NetSecAnalyzer 安装成功！")
        print("\n下一步:")
        print("1. 运行测试: python test_installation.py")
        print("2. 分析PCAP文件: python main.py -f flag.pcapng")
        print("3. 实时抓包: python main.py -r")
    else:
        print("\n⚠ 安装完成，但PCAP功能不可用")
        print("\n建议:")
        print("1. 安装WinPcap/Npcap (Windows)")
        print("2. 运行测试: python test_installation.py")
        print("3. 手动安装PCAP库")


if __name__ == "__main__":
    main()