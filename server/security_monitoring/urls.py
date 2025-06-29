# security_monitoring/urls.py
from django.urls import path
from . import views

app_name = 'security_monitoring'

urlpatterns = [
    path('dashboard/', views.security_dashboard, name='dashboard'),
    path('events/', views.security_events, name='events'),
    path('events/<int:event_id>/', views.security_event_detail, name='event_detail'),
    path('alerts/', views.security_alerts, name='alerts'),
    path('csp-violation/', views.csp_violation_report, name='csp_violation'),
    path('whitelist/', views.ip_whitelist, name='ip_whitelist'),
    path('blacklist/', views.ip_blacklist, name='ip_blacklist'),
    path('threat-intel/', views.threat_intelligence, name='threat_intelligence'),
]