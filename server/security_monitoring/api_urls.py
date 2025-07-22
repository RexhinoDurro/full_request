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
]