from django.shortcuts import render, redirect
from django.contrib import messages
from .models import UploadedFile
import os
from datetime import datetime
from collections import Counter
import random
import sys
import time
import signal
import argparse
from typing import Dict, List, Any, Optional

# 修复导入路径 - pcap_agent在当前目录下
current_dir = os.path.dirname(os.path.abspath(__file__))  # traffic目录
pcap_agent_path = os.path.join(current_dir, 'agent')
sys.path.insert(0, pcap_agent_path)

# 直接从main模块导入
from main import NetSecAnalyzer, print_banner

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False




def process_file_content(content, filename):
    # 对于pcap文件，这个函数不会被调用，因为pcap是二进制文件
    return content


def analyze_file_metadata(filename, content):
    # 对于pcap文件，返回基本信息
    metadata = {
        'file_size': len(content) if isinstance(content, bytes) else len(content.encode('utf-8')),
        'file_type': 'pcap'
    }
    return metadata


def index(request):
    if request.method == 'POST':
        uploaded_file = request.FILES.get('pcap_file')

        if not uploaded_file:
            messages.error(request, '请选择一个文件')
            return render(request, 'traffic/upload.html')

        if not uploaded_file.name.endswith(('.pcap', '.pcapng', '.cap')):
            messages.error(request, '请上传pcap格式的文件 (.pcap, .pcapng, .cap)')
            return render(request, 'traffic/upload.html')

        try:
            # 创建临时文件来保存上传的pcap文件
            temp_dir = 'temp_pcap'
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
            
            temp_file_path = os.path.join(temp_dir, uploaded_file.name)
            
            with open(temp_file_path, 'wb') as temp_file:
                for chunk in uploaded_file.chunks():
                    temp_file.write(chunk)
            
            # 分析pcap文件
            # analysis_result, log_content = analyze_pcap_file(temp_file_path, uploaded_file.name)

            """主函数"""
            
            silent_mode = True
            log_level = 'WARNING'
            
            # 初始化分析器
            analyzer = NetSecAnalyzer('./pcap_agent/config.yaml', silent_mode=silent_mode)
            analyzer.logger.setLevel(log_level)
            
            # try:
            result = {}
            
            # 文件分析模式
            analyzer._init_fluidai_client()
            result = analyzer.analyze_pcap_file(
                file_path=temp_file_path,
            )
            # 打印结果摘要
            if result:
                analyzer.print_analysis_summary(result)
                log_content = analyzer.generate_analysis_summary(result)
            
            print("\n分析完成！")
            
            # except KeyboardInterrupt:
            #     print("\n用户中断操作")
            #     analyzer.stop()
            # except Exception as e:
            #     print(f"\n发生错误: {e}")
            #     analyzer.logger.error(f"程序异常: {e}", exc_info=True)
            #     sys.exit(1)

            # ======================================================
            
            # if analysis_result is None:
            #     # messages.error(request, f'文件分析失败: {log_content}')
            #     return render(request, 'traffic/upload.html')
            
            # 生成分析结果文件名：包文件名(不含扩展名)+时间随机数.txt
            original_name = os.path.splitext(uploaded_file.name)[0]  # 去掉扩展名
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            random_num = random.randint(1000, 9999)
            analysis_filename = f"{original_name}_{timestamp}_{random_num}.txt"
            
            # 保存分析结果到数据库
            file_record = UploadedFile.objects.create(
                filename=analysis_filename,
                content=log_content
            )
            
            # 清理临时文件
            os.remove(temp_file_path)

            messages.success(request, f'文件 {uploaded_file.name} 分析结果: {analysis_filename}')
            return redirect('index')

        except Exception as e:
            messages.error(request, f'文件处理失败: {str(e)}')
            return render(request, 'traffic/upload.html')

    return render(request, 'traffic/upload.html')


def upload_file(request):
    # 重定向到index页面
    return redirect('index')


def file_list(request):
    """文件列表页面"""
    uploaded_files = UploadedFile.objects.all().order_by('-uploaded_at')
    return render(request, 'traffic/file_list.html', {'uploaded_files': uploaded_files})


def file_detail(request, file_id):
    """文件详情页面"""
    try:
        file_record = UploadedFile.objects.get(id=file_id)
        return render(request, 'traffic/file_detail.html', {'file_record': file_record})
    except UploadedFile.DoesNotExist:
        messages.error(request, '文件不存在')
        return redirect('file_list')


def delete_file(request, file_id):
    """删除文件"""
    try:
        file_record = UploadedFile.objects.get(id=file_id)
        filename = file_record.filename
        file_record.delete()
        messages.success(request, f'文件 {filename} 删除成功！')
    except UploadedFile.DoesNotExist:
        messages.error(request, '文件不存在')
    
    return redirect('file_list')