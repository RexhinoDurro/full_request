# submissions/urls.py - Updated with new money-related endpoints
from django.urls import path
from . import views

urlpatterns = [
    # Public endpoint for form submission
    path('submit/', views.submit_form, name='submit_form'),
    
    # Admin endpoints (require authentication)
    path('admin/submissions/', views.SubmissionListView.as_view(), name='submission_list'),
    path('admin/submissions/<int:pk>/', views.SubmissionDetailView.as_view(), name='submission_detail'),
    path('admin/submissions/<int:pk>/delete/', views.delete_submission, name='delete_submission'),
    path('admin/submissions/delete-all/', views.delete_all_submissions, name='delete_all_submissions'),
    path('admin/submissions/download/', views.download_submissions_excel, name='download_submissions'),
    path('admin/filter-options/', views.get_filter_options, name='filter_options'),
    path('admin/stats/', views.submission_stats, name='submission_stats'),
    
    # 🔧 NEW: Investment and money-related endpoints
    path('admin/investment-summary/', views.get_investment_summary, name='investment_summary'),
    path('admin/submissions/bulk-anonymize/', views.bulk_anonymize_submissions, name='bulk_anonymize'),
    
    # 🔧 NEW: System monitoring endpoints
    path('admin/health-check/', views.system_health_check, name='system_health_check'),
    
    # 🔧 NEW: Debug and testing endpoints (remove in production)
    path('admin/test-money-parsing/', views.test_money_parsing, name='test_money_parsing'),
]