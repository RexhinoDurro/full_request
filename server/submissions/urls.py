from django.urls import path
from . import views

urlpatterns = [
    # Public endpoint for form submission
    path('submit/', views.submit_form, name='submit_form'),
    
    # Admin endpoints (require authentication)
    path('admin/submissions/', views.SubmissionListView.as_view(), name='submission_list'),
    path('admin/submissions/<int:pk>/', views.SubmissionDetailView.as_view(), name='submission_detail'),
    path('admin/submissions/download/', views.download_submissions_excel, name='download_submissions'),
    path('admin/stats/', views.submission_stats, name='submission_stats'),
]