# server/security_monitoring/api_urls.py - New file for security API URLs
from django.urls import path
from . import api_views

app_name = 'security_api'

urlpatterns = [
    # Security Dashboard
    path('dashboard/', api_views.security_dashboard_api, name='dashboard'),
    
    # Security Events
    path('events/', api_views.security_events_api, name='events_list'),
    path('events/<int:event_id>/', api_views.security_event_detail_api, name='event_detail'),
    path('events/<int:event_id>/resolve/', api_views.resolve_security_event, name='resolve_event'),
    
    # IP Management
    path('whitelist/', api_views.ip_whitelist_api, name='whitelist_list'),
    path('whitelist/add/', api_views.add_ip_to_whitelist, name='whitelist_add'),
    
    path('blacklist/', api_views.ip_blacklist_api, name='blacklist_list'),
    path('blacklist/add/', api_views.add_ip_to_blacklist, name='blacklist_add'),
    path('blacklist/<int:blacklist_id>/', api_views.remove_ip_from_blacklist, name='blacklist_remove'),
]

