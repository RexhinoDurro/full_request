from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

urlpatterns = [
    path('login/', views.login, name='admin_login'),
    path('logout/', views.logout, name='admin_logout'),
    path('profile/', views.profile, name='admin_profile'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('create-admin/', views.create_admin, name='create_admin'),  # Remove in production
]