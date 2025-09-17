from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path('upload/', views.upload_file, name='upload_file'),
    path('view/<int:file_id>/', views.view_file_content, name='view_file_content'),
]