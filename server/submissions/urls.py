# server/submissions/urls.py - COMPLETE VERSION with Excel download
from django.urls import path
from . import views

urlpatterns = [
    # Public endpoint for form submission
    path('submit/', views.submit_form, name='submit_form'),
    
    # Admin endpoints (require authentication)
    path('admin/submissions/', views.SubmissionListView.as_view(), name='submission_list'),
    path('admin/submissions/<int:pk>/', views.SubmissionDetailView.as_view(), name='submission_detail'),
    path('admin/submissions/<int:pk>/delete/', views.delete_submission, name='delete_submission'),
    
    # 🔧 ADDED: Excel download endpoint
    path('admin/submissions/download/', views.download_submissions_excel, name='download_submissions_excel'),
    
    # 🔧 ADDED: Admin management endpoints
    path('admin/submissions/delete-all/', views.delete_all_submissions, name='delete_all_submissions'),
    path('admin/filter-options/', views.get_filter_options, name='get_filter_options'),
    path('admin/stats/', views.submission_stats, name='submission_stats'),
    
    # Emergency endpoint
    path('admin/emergency-lockdown/', views.emergency_security_lockdown, name='emergency_lockdown'),
]