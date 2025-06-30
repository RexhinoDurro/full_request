# authentication/urls.py - SECURITY FIXED

from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

urlpatterns = [
    path('login/', views.login, name='admin_login'),
    path('logout/', views.logout, name='admin_logout'),
    path('profile/', views.profile, name='admin_profile'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # ⚠️ REMOVED: create-admin endpoint - SECURITY RISK
    # Admin users should only be created via:
    # 1. Django management commands: python manage.py createsuperuser
    # 2. Existing superusers through Django admin
    # 3. During deployment via build scripts with proper environment variables
]