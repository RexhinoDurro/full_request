from django.urls import path
from . import views

urlpatterns = [
    # Public endpoint for form submission
    path('submit/', views.submit_form, name='submit_form'),
    
    # Admin endpoints (require authentication)
    path('admin/submissions/', views.SubmissionListView.as_view(), name='submission_list'),
    path('admin/submissions/<int:pk>/', views.SubmissionDetailView.as_view(), name='submission_detail'),
    path('admin/submissions/<int:pk>/delete/', views.delete_submission, name='delete_submission'),
    
    # Emergency endpoint
    path('admin/emergency-lockdown/', views.emergency_security_lockdown, name='emergency_lockdown'),
]
 