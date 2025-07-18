# server/security_monitoring/api_views.py - New file for API endpoints
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
from .models import SecurityEvent, IPWhitelist, IPBlacklist, SecurityAlert, ThreatIntelligence
from .utils import get_client_ip, log_security_event

@api_view(['GET'])
@permission_classes([IsAdminUser])
def security_dashboard_api(request):
    """Security dashboard API endpoint matching admin client expectations"""
    try:
        now = timezone.now()
        
        # Last 24 hours stats
        last_24h = now - timedelta(hours=24)
        events_24h = SecurityEvent.objects.filter(timestamp__gte=last_24h)
        
        # Last 7 days stats
        last_7d = now - timedelta(days=7)
        events_7d = SecurityEvent.objects.filter(timestamp__gte=last_7d)
        
        # Top threats
        top_threats = list(
            events_24h.values('event_type')
            .annotate(count=Count('event_type'))
            .order_by('-count')[:5]
        )
        
        # Top IPs
        top_ips = list(
            events_24h.values('ip_address')
            .annotate(count=Count('ip_address'))
            .order_by('-count')[:10]
        )
        
        # Threat trends (last 7 days)
        threat_trends = []
        for i in range(7):
            date = (now - timedelta(days=i)).date()
            day_events = events_7d.filter(timestamp__date=date)
            
            trend_data = {
                'date': date.isoformat(),
                'total': day_events.count(),
                'critical': day_events.filter(severity='CRITICAL').count(),
                'high': day_events.filter(severity='HIGH').count(),
                'medium': day_events.filter(severity='MEDIUM').count(),
                'low': day_events.filter(severity='LOW').count(),
            }
            threat_trends.append(trend_data)
        
        threat_trends.reverse()  # Chronological order
        
        dashboard_data = {
            'events_24h': events_24h.count(),
            'events_7d': events_7d.count(),
            'critical_events_24h': events_24h.filter(severity='CRITICAL').count(),
            'high_events_24h': events_24h.filter(severity='HIGH').count(),
            'top_threats': top_threats,
            'top_ips': top_ips,
            'threat_trends': threat_trends,
        }
        
        return Response({
            'success': True,
            'data': dashboard_data
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'message': f'Failed to load dashboard: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAdminUser])
def security_events_api(request):
    """Security events list API endpoint with filtering"""
    try:
        # Get query parameters
        limit = int(request.GET.get('limit', 50))
        offset = int(request.GET.get('offset', 0))
        severity = request.GET.get('severity')
        event_type = request.GET.get('event_type')
        resolved = request.GET.get('resolved')
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        
        # Base queryset
        queryset = SecurityEvent.objects.select_related('user').all()
        
        # Apply filters
        if severity:
            queryset = queryset.filter(severity=severity)
        if event_type:
            queryset = queryset.filter(event_type=event_type)
        if resolved is not None:
            queryset = queryset.filter(resolved=resolved.lower() == 'true')
        if date_from:
            try:
                start_date = timezone.datetime.strptime(date_from, '%Y-%m-%d').date()
                queryset = queryset.filter(timestamp__date__gte=start_date)
            except ValueError:
                pass
        if date_to:
            try:
                end_date = timezone.datetime.strptime(date_to, '%Y-%m-%d').date()
                queryset = queryset.filter(timestamp__date__lte=end_date)
            except ValueError:
                pass
        
        # Get total count
        total_count = queryset.count()
        
        # Apply pagination
        events = queryset.order_by('-timestamp')[offset:offset + limit]
        
        # Serialize events
        events_data = []
        for event in events:
            event_data = {
                'id': event.id,
                'event_type': event.event_type,
                'severity': event.severity,
                'ip_address': event.ip_address,
                'user_agent': event.user_agent,
                'description': event.description,
                'timestamp': event.timestamp.isoformat(),
                'resolved': event.resolved,
                'metadata': event.metadata,
            }
            
            if event.user:
                event_data['user'] = {
                    'id': event.user.id,
                    'username': event.user.username,
                }
            
            events_data.append(event_data)
        
        # Calculate pagination
        next_url = None
        previous_url = None
        
        if offset + limit < total_count:
            next_url = f"?offset={offset + limit}&limit={limit}"
        
        if offset > 0:
            previous_offset = max(0, offset - limit)
            previous_url = f"?offset={previous_offset}&limit={limit}"
        
        return Response({
            'success': True,
            'data': {
                'results': events_data,
                'count': total_count,
                'next': next_url,
                'previous': previous_url,
            }
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'message': f'Failed to load events: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAdminUser])
def security_event_detail_api(request, event_id):
    """Get detailed information about a specific security event"""
    try:
        event = SecurityEvent.objects.select_related('user').get(id=event_id)
        
        event_data = {
            'id': event.id,
            'event_type': event.event_type,
            'severity': event.severity,
            'ip_address': event.ip_address,
            'user_agent': event.user_agent,
            'description': event.description,
            'timestamp': event.timestamp.isoformat(),
            'resolved': event.resolved,
            'metadata': event.metadata,
        }
        
        if event.user:
            event_data['user'] = {
                'id': event.user.id,
                'username': event.user.username,
            }
        
        return Response({
            'success': True,
            'data': event_data
        })
        
    except SecurityEvent.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Security event not found'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([IsAdminUser])
def resolve_security_event(request, event_id):
    """Mark a security event as resolved"""
    try:
        event = SecurityEvent.objects.get(id=event_id)
        event.resolved = True
        event.save()
        
        # Log the resolution
        log_security_event(
            'ADMIN_ACTION',
            'LOW',
            get_client_ip(request),
            request.META.get('HTTP_USER_AGENT', ''),
            request.user,
            f'Security event {event_id} resolved by {request.user.username}'
        )
        
        return Response({
            'success': True,
            'message': 'Security event resolved successfully'
        })
        
    except SecurityEvent.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Security event not found'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([IsAdminUser])
def ip_whitelist_api(request):
    """Get IP whitelist"""
    try:
        whitelist = IPWhitelist.objects.select_related('created_by').filter(is_active=True)
        
        whitelist_data = []
        for entry in whitelist:
            whitelist_data.append({
                'id': entry.id,
                'ip_address': entry.ip_address,
                'description': entry.description,
                'created_at': entry.created_at.isoformat(),
                'is_active': entry.is_active,
                'created_by': entry.created_by.username if entry.created_by else None,
            })
        
        return Response({
            'success': True,
            'data': whitelist_data
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'message': f'Failed to load whitelist: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAdminUser])
def add_ip_to_whitelist(request):
    """Add IP to whitelist"""
    try:
        ip_address = request.data.get('ip_address')
        description = request.data.get('description', '')
        
        if not ip_address:
            return Response({
                'success': False,
                'message': 'IP address is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if already exists
        if IPWhitelist.objects.filter(ip_address=ip_address, is_active=True).exists():
            return Response({
                'success': False,
                'message': 'IP address already in whitelist'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create whitelist entry
        IPWhitelist.objects.create(
            ip_address=ip_address,
            description=description,
            created_by=request.user,
            is_active=True
        )
        
        # Log the action
        log_security_event(
            'ADMIN_ACTION',
            'MEDIUM',
            get_client_ip(request),
            request.META.get('HTTP_USER_AGENT', ''),
            request.user,
            f'IP {ip_address} added to whitelist by {request.user.username}'
        )
        
        return Response({
            'success': True,
            'message': 'IP address added to whitelist successfully'
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'message': f'Failed to add IP to whitelist: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAdminUser])
def ip_blacklist_api(request):
    """Get IP blacklist"""
    try:
        blacklist = IPBlacklist.objects.all()
        
        blacklist_data = []
        for entry in blacklist:
            blacklist_data.append({
                'id': entry.id,
                'ip_address': entry.ip_address,
                'reason': entry.reason,
                'blocked_until': entry.blocked_until.isoformat() if entry.blocked_until else None,
                'permanent': entry.permanent,
                'created_at': entry.created_at.isoformat(),
            })
        
        return Response({
            'success': True,
            'data': blacklist_data
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'message': f'Failed to load blacklist: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAdminUser])
def add_ip_to_blacklist(request):
    """Add IP to blacklist"""
    try:
        ip_address = request.data.get('ip_address')
        reason = request.data.get('reason', 'Manual blacklist')
        permanent = request.data.get('permanent', False)
        hours = request.data.get('hours')
        
        if not ip_address:
            return Response({
                'success': False,
                'message': 'IP address is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        blocked_until = None
        if not permanent and hours:
            blocked_until = timezone.now() + timedelta(hours=int(hours))
        
        # Create or update blacklist entry
        IPBlacklist.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'reason': reason,
                'blocked_until': blocked_until,
                'permanent': permanent,
            }
        )
        
        # Log the action
        log_security_event(
            'ADMIN_ACTION',
            'HIGH',
            get_client_ip(request),
            request.META.get('HTTP_USER_AGENT', ''),
            request.user,
            f'IP {ip_address} added to blacklist by {request.user.username}'
        )
        
        return Response({
            'success': True,
            'message': 'IP address added to blacklist successfully'
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'message': f'Failed to add IP to blacklist: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def remove_ip_from_blacklist(request, blacklist_id):
    """Remove IP from blacklist"""
    try:
        entry = IPBlacklist.objects.get(id=blacklist_id)
        ip_address = entry.ip_address
        entry.delete()
        
        # Log the action
        log_security_event(
            'ADMIN_ACTION',
            'MEDIUM',
            get_client_ip(request),
            request.META.get('HTTP_USER_AGENT', ''),
            request.user,
            f'IP {ip_address} removed from blacklist by {request.user.username}'
        )
        
        return Response({
            'success': True,
            'message': 'IP address removed from blacklist successfully'
        })
        
    except IPBlacklist.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Blacklist entry not found'
        }, status=status.HTTP_404_NOT_FOUND)