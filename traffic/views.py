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

    # 获取已上传的文件列表
    uploaded_files = UploadedFile.objects.all().order_by('-uploaded_at')
    return render(request, 'traffic/upload.html', {'uploaded_files': uploaded_files})


def view_file_content(request, file_id):
    try:
        file_record = UploadedFile.objects.get(id=file_id)
        return JsonResponse({
            'filename': file_record.filename,
            'content': file_record.content,
            'uploaded_at': file_record.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    except UploadedFile.DoesNotExist:
        return JsonResponse({'error': '文件不存在'}, status=404)