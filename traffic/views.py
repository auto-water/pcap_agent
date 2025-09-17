from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from .models import UploadedFile
import os


def index(request):
    return HttpResponse("Hello, world. You're at the traffic index.")


def upload_file(request):
    if request.method == 'POST':
        uploaded_file = request.FILES.get('txt_file')

        if not uploaded_file:
            messages.error(request, '请选择一个文件')
            return render(request, 'traffic/upload.html')

        if not uploaded_file.name.endswith('.txt'):
            messages.error(request, '请上传txt格式的文件')
            return render(request, 'traffic/upload.html')

        try:
            # 读取文件内容
            content = uploaded_file.read().decode('utf-8')

            # 保存到数据库
            file_record = UploadedFile.objects.create(
                filename=uploaded_file.name,
                content=content
            )

            messages.success(request, f'文件 {uploaded_file.name} 上传成功！')
            return redirect('upload_file')

        except Exception as e:
            messages.error(request, f'文件处理失败: {str(e)}')
            return render(request, 'traffic/upload.html')

    return render(request, 'traffic/upload.html')


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


def file_delete(request, file_id):
    """删除文件"""
    if request.method == 'POST':
        try:
            file_record = UploadedFile.objects.get(id=file_id)
            file_record.delete()
            messages.success(request, '文件删除成功')
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