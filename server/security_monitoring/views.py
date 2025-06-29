# security_monitoring/views.py
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import user_passes_test
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.core.paginator import Paginator
from datetime import timedelta
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.db.models import Count, Q
from .models import SecurityEvent, SecurityAlert, IPWhitelist, IPBlacklist, ThreatIntelligence
from .utils import get_client_ip, log_security_event

def is_admin(user):
    return user.is_authenticated and user.is_staff

@user_passes_test(is_admin)
def security_dashboard(request):
    """Security dashboard view"""
    now = timezone.now()
    
    # Last 24 hours stats
    last_24h = now - timedelta(hours=24)
    events_24h = SecurityEvent.objects.filter(timestamp__gte=last_24h)
    
    # Last 7 days stats
    last_7d = now - timedelta(days=7)
    events_7d = SecurityEvent.objects.filter(timestamp__gte=last_7d)
    
    context = {
        'events_24h': events_24h.count(),
        'events_7d': events_7d.count(),
        'critical_events_24h': events_24h.filter(severity='CRITICAL').count(),
        'high_events_24h': events_24h.filter(severity='HIGH').count(),
        'unresolved_alerts': SecurityAlert.objects.filter(status='OPEN').count(),
        'blacklisted_ips': IPBlacklist.objects.filter(
            Q(permanent=True) | Q(blocked_until__gt=now)
        ).count(),
        'recent_events': events_24h.order_by('-timestamp')[:10],
        'top_event_types': events_7d.values('event_type').annotate(
            count=Count('event_type')
        ).order_by('-count')[:5],
    }
    
    return render(request, 'security_monitoring/dashboard.html', context)

@user_passes_test(is_admin)
def security_events(request):
    """Security events list view"""
    events = SecurityEvent.objects.select_related('user').order_by('-timestamp')
    
    # Filtering
    severity = request.GET.get('severity')
    event_type = request.GET.get('event_type')
    resolved = request.GET.get('resolved')
    
    if severity:
        events = events.filter(severity=severity)
    if event_type:
        events = events.filter(event_type=event_type)
    if resolved:
        events = events.filter(resolved=resolved.lower() == 'true')
    
    # Pagination
    paginator = Paginator(events, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'severity_choices': SecurityEvent.SEVERITY_LEVELS,
        'event_type_choices': SecurityEvent.EVENT_TYPES,
        'current_filters': {
            'severity': severity,
            'event_type': event_type,
            'resolved': resolved,
        }
    }
    
    return render(request, 'security_monitoring/events.html', context)

@api_view(['POST'])
@permission_classes([AllowAny])
def csp_violation_report(request):
    """Endpoint for CSP violation reports"""
    try:
        violation_data = request.data
        
        log_security_event(
            event_type='CSP_VIOLATION',
            severity='MEDIUM',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            description='Content Security Policy violation',
            metadata=violation_data
        )
        
        return Response({'status': 'recorded'})
    except Exception as e:
        return Response({'error': str(e)}, status=400)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def security_dashboard_api(request):
    """Security dashboard API endpoint"""
    now = timezone.now()
    
    # Last 24 hours stats
    last_24h = now - timedelta(hours=24)
    events_24h = SecurityEvent.objects.filter(timestamp__gte=last_24h)
    
    # Last 7 days stats
    last_7d = now - timedelta(days=7)
    events_7d = SecurityEvent.objects.filter(timestamp__gte=last_7d)
    
    dashboard_data = {
        'events_24h': events_24h.count(),
        'events_7d': events_7d.count(),
        'critical_events_24h': events_24h.filter(severity='CRITICAL').count(),
        'high_events_24h': events_24h.filter(severity='HIGH').count(),
        'top_threats': list(
            events_24h.values('event_type')
            .annotate(count=Count('event_type'))
            .order_by('-count')[:5]
        ),
        'top_ips': list(
            events_24h.values('ip_address')
            .annotate(count=Count('ip_address'))
            .order_by('-count')[:10]
        ),
        'threat_trends': get_threat_trends(events_7d),
    }
    
    return Response(dashboard_data)

def get_threat_trends(events_queryset):
    """Get threat trends over time"""
    trends = []
    for i in range(7):
        date = timezone.now().date() - timedelta(days=i)
        day_events = events_queryset.filter(timestamp__date=date)
        
        trends.append({
            'date': date.isoformat(),
            'total': day_events.count(),
            'critical': day_events.filter(severity='CRITICAL').count(),
            'high': day_events.filter(severity='HIGH').count(),
            'medium': day_events.filter(severity='MEDIUM').count(),
            'low': day_events.filter(severity='LOW').count(),
        })
    
    return trends

# Placeholder views for other endpoints
@user_passes_test(is_admin)
def security_event_detail(request, event_id):
    event = get_object_or_404(SecurityEvent, id=event_id)
    return render(request, 'security_monitoring/event_detail.html', {'event': event})

@user_passes_test(is_admin)
def security_alerts(request):
    alerts = SecurityAlert.objects.order_by('-created_at')
    return render(request, 'security_monitoring/alerts.html', {'alerts': alerts})

@user_passes_test(is_admin)
def ip_whitelist(request):
    whitelist = IPWhitelist.objects.order_by('-created_at')
    return render(request, 'security_monitoring/ip_whitelist.html', {'whitelist': whitelist})

@user_passes_test(is_admin)
def ip_blacklist(request):
    blacklist = IPBlacklist.objects.order_by('-created_at')
    return render(request, 'security_monitoring/ip_blacklist.html', {'blacklist': blacklist})

@user_passes_test(is_admin)
def threat_intelligence(request):
    threats = ThreatIntelligence.objects.filter(is_active=True).order_by('-last_seen')
    return render(request, 'security_monitoring/threat_intelligence.html', {'threats': threats})