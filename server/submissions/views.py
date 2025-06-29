# submissions/views.py - Enhanced secure views
import re
from django.http import HttpResponse
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django_ratelimit.decorators import ratelimit
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache
from django.utils.decorators import method_decorator
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
import logging
import hashlib
import json
import bleach

from .models import Submission
from .serializers import SecureSubmissionCreateSerializer, SubmissionListSerializer, SubmissionDetailSerializer
from security_monitoring.models import SecurityEvent
from security_monitoring.utils import get_client_ip

logger = logging.getLogger('security_monitoring')

# Custom throttle classes
class SubmissionRateThrottle(AnonRateThrottle):
    rate = '5/min'
    
class LoginRateThrottle(AnonRateThrottle):
    rate = '3/5min'

def log_security_event(event_type, severity, request, description, metadata=None):
    """Helper function to log security events"""
    try:
        SecurityEvent.objects.create(
            event_type=event_type,
            severity=severity,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            user=request.user if request.user.is_authenticated else None,
            description=description,
            metadata=metadata or {}
        )
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

def detect_form_spam(request, form_data):
    """Detect form spam using various techniques"""
    client_ip = get_client_ip(request)
    
    # Rate limiting check
    cache_key = f"form_submissions:{client_ip}"
    recent_submissions = cache.get(cache_key, 0)
    
    if recent_submissions >= 3:  # Max 3 submissions per hour
        return True, "Too many submissions from this IP"
    
    # Content-based spam detection
    spam_keywords = [
        'viagra', 'casino', 'lottery', 'winner', 'congratulations',
        'click here', 'free money', 'make money fast', 'work from home',
        'weight loss', 'diet pills', 'enlargement', 'pills'
    ]
    
    all_text = ' '.join([
        str(form_data.get(field, '')) for field in form_data.keys()
    ]).lower()
    
    spam_score = sum(1 for keyword in spam_keywords if keyword in all_text)
    
    if spam_score >= 2:
        return True, f"Spam content detected (score: {spam_score})"
    
    # Check for excessive length (potential spam)
    total_length = sum(len(str(form_data.get(field, ''))) for field in form_data.keys())
    if total_length > 5000:
        return True, "Submission too long"
    
    # Check for repeated characters (spam pattern)
    if re.search(r'(.)\1{10,}', all_text):
        return True, "Suspicious repeated characters"
    
    return False, ""

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([SubmissionRateThrottle])
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@csrf_protect
@never_cache
def submit_form(request):
    """Ultra-secure public endpoint for form submission"""
    
    client_ip = get_client_ip(request)
    
    try:
        # Log submission attempt
        log_security_event(
            'FORM_SUBMISSION', 'LOW', request,
            f'Form submission attempt from {client_ip}'
        )
        
        # Spam detection
        is_spam, spam_reason = detect_form_spam(request, request.data)
        if is_spam:
            log_security_event(
                'FORM_SPAM', 'MEDIUM', request,
                f'Spam detected: {spam_reason}',
                {'form_data': request.data}
            )
            return Response({
                'success': False,
                'message': 'Submission blocked by spam filter'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        # Validate and create submission
        serializer = SecureSubmissionCreateSerializer(data=request.data)
        
        if serializer.is_valid():
            # Create hash of submission data for duplicate detection
            data_hash = hashlib.md5(
                json.dumps(serializer.validated_data, sort_keys=True).encode()
            ).hexdigest()
            
            # Check for duplicate submissions
            cache_key = f"submission_hash:{data_hash}"
            if cache.get(cache_key):
                log_security_event(
                    'FORM_SPAM', 'MEDIUM', request,
                    'Duplicate submission detected'
                )
                return Response({
                    'success': False,
                    'message': 'Duplicate submission detected'
                }, status=status.HTTP_409_CONFLICT)
            
            # Save submission
            submission = serializer.save(ip_address=client_ip)
            
            # Cache submission hash to prevent duplicates
            cache.set(cache_key, True, 3600)  # 1 hour
            
            # Update rate limiting counter
            cache_key = f"form_submissions:{client_ip}"
            cache.set(cache_key, cache.get(cache_key, 0) + 1, 3600)
            
            log_security_event(
                'FORM_SUBMISSION', 'LOW', request,
                f'Successful form submission ID: {submission.id}'
            )
            
            return Response({
                'success': True,
                'message': 'Form submitted successfully',
                'submission_id': submission.id
            }, status=status.HTTP_201_CREATED)
        
        else:
            # Log validation errors
            log_security_event(
                'FORM_SUBMISSION', 'LOW', request,
                f'Form validation failed: {serializer.errors}',
                {'validation_errors': serializer.errors}
            )
            
            return Response({
                'success': False,
                'message': 'Form validation failed',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        logger.error(f"Form submission error: {e}")
        log_security_event(
            'API_ERROR', 'HIGH', request,
            f'Form submission error: {str(e)}'
        )
        
        return Response({
            'success': False,
            'message': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(never_cache, name='dispatch')
class SecureSubmissionListView(generics.ListAPIView):
    """Ultra-secure admin endpoint to list submissions"""
    serializer_class = SubmissionListSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def dispatch(self, request, *args, **kwargs):
        # Log admin access
        if request.user.is_authenticated:
            log_security_event(
                'ADMIN_ACCESS', 'LOW', request,
                f'Admin {request.user.username} accessed submission list'
            )
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        """Enhanced queryset with security logging"""
        queryset = Submission.objects.all()
        
        # Apply filters securely
        filters = self.request.query_params
        
        # Validate and sanitize filter parameters
        safe_filters = {}
        for key, value in filters.items():
            # Only allow known filter keys
            allowed_filters = [
                'date_from', 'date_to', 'date_preset', 'service_type',
                'issue_timeframe', 'country', 'search'
            ]
            if key in allowed_filters:
                # Sanitize filter values
                safe_value = bleach.clean(value, tags=[], strip=True)
                safe_filters[key] = safe_value[:100]  # Limit length
        
        # Apply date filtering
        if safe_filters.get('date_preset'):
            preset = safe_filters['date_preset']
            now = timezone.now()
            
            if preset == 'today':
                start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
                queryset = queryset.filter(submitted_at__gte=start_date)
            elif preset == '1_week':
                start_date = now - timedelta(days=7)
                queryset = queryset.filter(submitted_at__gte=start_date)
            elif preset == '2_weeks':
                start_date = now - timedelta(days=14)
                queryset = queryset.filter(submitted_at__gte=start_date)
            elif preset == '30_days':
                start_date = now - timedelta(days=30)
                queryset = queryset.filter(submitted_at__gte=start_date)
        
        # Apply other filters with validation
        if safe_filters.get('service_type'):
            queryset = queryset.filter(step2__icontains=safe_filters['service_type'])
        
        if safe_filters.get('country'):
            # Validate country code format
            country = safe_filters['country']
            if re.match(r'^[A-Z]{2}$', country):
                queryset = queryset.filter(country=country)
        
        if safe_filters.get('search'):
            search_term = safe_filters['search']
            # Use Q objects safely
            from django.db.models import Q
            queryset = queryset.filter(
                Q(name__icontains=search_term) |
                Q(email__icontains=search_term)
            )
        
        # Log data access
        count = queryset.count()
        log_security_event(
            'DATA_ACCESS', 'LOW', self.request,
            f'Admin accessed {count} submissions with filters: {safe_filters}'
        )
        
        return queryset.order_by('-submitted_at')

@method_decorator(never_cache, name='dispatch')
class SecureSubmissionDetailView(generics.RetrieveAPIView):
    """Ultra-secure admin endpoint to view detailed submission"""
    queryset = Submission.objects.all()
    serializer_class = SubmissionDetailSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    
    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        
        # Log sensitive data access
        submission_id = kwargs.get('pk')
        log_security_event(
            'SENSITIVE_DATA_ACCESS', 'MEDIUM', request,
            f'Admin {request.user.username} viewed submission {submission_id}'
        )
        
        return response

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@throttle_classes([UserRateThrottle])
@ratelimit(key='user', rate='10/m', method='DELETE', block=True)
@never_cache
def secure_delete_submission(request, pk):
    """Ultra-secure admin endpoint to delete individual submission"""
    
    try:
        submission = Submission.objects.get(pk=pk)
        
        # Log deletion attempt
        log_security_event(
            'DATA_DELETION', 'HIGH', request,
            f'Admin {request.user.username} deleted submission {pk}',
            {'submission_data': {
                'id': submission.id,
                'name': submission.name,
                'email': submission.email,
                'submitted_at': submission.submitted_at.isoformat()
            }}
        )
        
        submission.delete()
        
        return Response({
            'success': True,
            'message': 'Submission deleted successfully'
        }, status=status.HTTP_200_OK)
        
    except Submission.DoesNotExist:
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'MEDIUM', request,
            f'Admin {request.user.username} attempted to delete non-existent submission {pk}'
        )
        return Response({
            'success': False,
            'message': 'Submission not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    except Exception as e:
        logger.error(f"Deletion error: {e}")
        log_security_event(
            'API_ERROR', 'HIGH', request,
            f'Error deleting submission {pk}: {str(e)}'
        )
        return Response({
            'success': False,
            'message': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([UserRateThrottle])
@ratelimit(key='user', rate='1/h', method='POST', block=True)  # Very restrictive
@never_cache
def secure_delete_all_submissions(request):
    """Ultra-secure admin endpoint to delete all submissions"""
    
    confirmation = request.data.get('confirmation')
    
    if confirmation != 'delete_permanently':
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'HIGH', request,
            f'Admin {request.user.username} attempted bulk deletion without proper confirmation'
        )
        return Response({
            'success': False,
            'message': 'Invalid confirmation. Type "delete_permanently" to confirm.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        count = Submission.objects.count()
        
        # Create backup before deletion
        backup_data = list(Submission.objects.values())
        
        # Log critical action
        log_security_event(
            'BULK_DATA_DELETION', 'CRITICAL', request,
            f'Admin {request.user.username} deleted ALL {count} submissions',
            {'backup_created': True, 'deletion_count': count}
        )
        
        # Perform deletion
        Submission.objects.all().delete()
        
        # Send alert email about bulk deletion
        from security_monitoring.utils import send_security_alert
        send_security_alert(
            'BULK_DATA_DELETION', 'CRITICAL',
            get_client_ip(request),
            f'Admin {request.user.username} deleted all {count} submissions'
        )
        
        return Response({
            'success': True,
            'message': f'Successfully deleted {count} submissions'
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Bulk deletion error: {e}")
        log_security_event(
            'API_ERROR', 'CRITICAL', request,
            f'Error in bulk deletion: {str(e)}'
        )
        return Response({
            'success': False,
            'message': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)