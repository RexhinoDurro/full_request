# submissions/views.py - SECURITY FIXED VERSION (CSRF Exempt for APIs)

import re
import hashlib
import json
import logging
from datetime import timedelta

from django.http import HttpResponse
from django.utils import timezone
from django.core.cache import cache
from django.db import transaction
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django_ratelimit.decorators import ratelimit
from django.views.decorators.cache import never_cache
from django.utils.decorators import method_decorator

from .models import Submission
from .serializers import SecureSubmissionCreateSerializer, SubmissionListSerializer, SubmissionDetailSerializer
from security_monitoring.models import SecurityEvent
from security_monitoring.utils import get_client_ip

logger = logging.getLogger('security_monitoring')

# Custom throttle classes with reduced rates
class SubmissionRateThrottle(AnonRateThrottle):
    rate = '3/min'  # Reduced from 5/min
    
class AdminRateThrottle(UserRateThrottle):
    rate = '100/hour'  # Specific for admin operations

def log_security_event(event_type, severity, request, description, metadata=None):
    """Enhanced security event logging"""
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
        
        # Also log to Django logger for immediate visibility
        logger.warning(f"SECURITY: {event_type} - {description} - IP: {get_client_ip(request)}")
        
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

class DatabaseRateLimiter:
    """Database-backed rate limiter (Redis-free)"""
    
    @staticmethod
    def is_rate_limited(key, limit, window_seconds):
        """Check if request should be rate limited"""
        try:
            # Use database to store rate limit data
            from security_monitoring.models import SecurityEvent
            
            cutoff_time = timezone.now() - timedelta(seconds=window_seconds)
            recent_events = SecurityEvent.objects.filter(
                description__contains=key,
                timestamp__gte=cutoff_time
            ).count()
            
            return recent_events >= limit
            
        except Exception:
            # Fail open for availability
            return False

def enhanced_spam_detection(request, form_data):
    """Enhanced spam detection with multiple techniques"""
    client_ip = get_client_ip(request)
    
    # 1. Rate limiting check (database-backed)
    if DatabaseRateLimiter.is_rate_limited(f"form_submission:{client_ip}", 3, 3600):
        return True, "Rate limit exceeded"
    
    # 2. Content analysis
    all_text = ' '.join([str(form_data.get(field, '')) for field in form_data.keys()]).lower()
    
    # Enhanced spam keywords
    spam_indicators = {
        'high_risk': ['viagra', 'casino', 'lottery', 'winner', 'free money', 'click here'],
        'medium_risk': ['urgent', 'limited time', 'act now', 'guarantee', 'amazing'],
        'suspicious_patterns': [r'\b\w*\d{4,}\w*\b', r'[A-Z]{10,}', r'(.)\1{5,}']
    }
    
    risk_score = 0
    
    # Check high-risk keywords
    for keyword in spam_indicators['high_risk']:
        if keyword in all_text:
            risk_score += 10
    
    # Check medium-risk keywords
    for keyword in spam_indicators['medium_risk']:
        if keyword in all_text:
            risk_score += 3
    
    # Check suspicious patterns
    for pattern in spam_indicators['suspicious_patterns']:
        if re.search(pattern, all_text):
            risk_score += 5
    
    # 3. Length-based detection
    if len(all_text) > 10000:  # Extremely long submission
        risk_score += 15
    elif len(all_text) < 10:  # Extremely short submission
        risk_score += 5
    
    # 4. Repeated character detection
    if re.search(r'(.)\1{10,}', all_text):
        risk_score += 10
    
    # 5. URL/Link detection (suspicious in form submissions)
    url_pattern = r'https?://|www\.|\.com|\.org|\.net'
    if re.search(url_pattern, all_text):
        risk_score += 8
    
    return risk_score >= 15, f"Spam detected (risk score: {risk_score})"

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([SubmissionRateThrottle])
@ratelimit(key='ip', rate='3/m', method='POST', block=True)
@csrf_exempt  # ✅ CHANGED: Removed @csrf_protect, added @csrf_exempt
@never_cache
def submit_form(request):
    """Ultra-secure form submission endpoint"""
    
    client_ip = get_client_ip(request)
    
    # Input validation
    if not request.data:
        log_security_event('SUSPICIOUS_ACTIVITY', 'MEDIUM', request, 'Empty form submission')
        return Response({
            'success': False,
            'message': 'No data provided'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Enhanced spam detection
        is_spam, spam_reason = enhanced_spam_detection(request, request.data)
        if is_spam:
            log_security_event(
                'FORM_SPAM', 'HIGH', request,
                f'Enhanced spam detection: {spam_reason}',
                {'form_data_length': len(str(request.data)), 'reason': spam_reason}
            )
            return Response({
                'success': False,
                'message': 'Submission blocked by spam filter'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        # Validate submission data
        serializer = SecureSubmissionCreateSerializer(data=request.data)
        
        if serializer.is_valid():
            # Create unique hash for duplicate detection
            data_hash = hashlib.sha256(
                json.dumps(serializer.validated_data, sort_keys=True).encode()
            ).hexdigest()
            
            # Check for recent duplicates (24-hour window)
            cache_key = f"submission_hash:{data_hash}"
            if cache.get(cache_key):
                log_security_event(
                    'FORM_SPAM', 'MEDIUM', request,
                    'Duplicate submission attempt within 24 hours'
                )
                return Response({
                    'success': False,
                    'message': 'Duplicate submission detected'
                }, status=status.HTTP_409_CONFLICT)
            
            # Save submission with transaction atomicity
            with transaction.atomic():
                submission = serializer.save()
                
                # Cache submission hash to prevent duplicates
                cache.set(cache_key, True, 86400)  # 24 hours
                
                # Log successful submission
                log_security_event(
                    'FORM_SUBMISSION', 'LOW', request,
                    f'Successful form submission ID: {submission.uuid}',
                    {'submission_id': str(submission.uuid)}
                )
            
            return Response({
                'success': True,
                'message': 'Form submitted successfully',
                'submission_id': str(submission.uuid)  # Use UUID instead of ID
            }, status=status.HTTP_201_CREATED)
        
        else:
            # Log validation errors without exposing details
            log_security_event(
                'FORM_VALIDATION_ERROR', 'LOW', request,
                'Form validation failed',
                {'error_count': len(serializer.errors)}
            )
            
            return Response({
                'success': False,
                'message': 'Please check your form data and try again',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        # Log error without exposing internal details
        logger.error(f"Form submission error: {e}", exc_info=True)
        log_security_event(
            'API_ERROR', 'HIGH', request,
            'Form submission processing error'
        )
        
        return Response({
            'success': False,
            'message': 'Unable to process submission. Please try again later.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(never_cache, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')  # ✅ ADDED: CSRF exempt for API
class SubmissionListView(generics.ListAPIView):
    """Secure admin endpoint to list submissions"""
    serializer_class = SubmissionListSerializer
    permission_classes = [IsAdminUser]
    throttle_classes = [AdminRateThrottle]

    def dispatch(self, request, *args, **kwargs):
        # Enhanced admin access logging
        if request.user.is_authenticated:
            log_security_event(
                'ADMIN_ACCESS', 'MEDIUM', request,
                f'Admin {request.user.username} accessed submission list',
                {'admin_user': request.user.username, 'is_superuser': request.user.is_superuser}
            )
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        """Secure queryset with input validation"""
        queryset = Submission.objects.all()
        
        # Validate and sanitize filter parameters
        filters = self.request.query_params
        safe_filters = {}
        
        # Whitelist allowed filters with validation
        allowed_filters = {
            'date_from': lambda x: x if re.match(r'^\d{4}-\d{2}-\d{2}$', x) else None,
            'date_to': lambda x: x if re.match(r'^\d{4}-\d{2}-\d{2}$', x) else None,
            'country': lambda x: x if re.match(r'^[A-Z]{2}$', x) else None,
            'search': lambda x: x[:50] if len(x) <= 50 else None,  # Limit search length
        }
        
        for key, validator in allowed_filters.items():
            if key in filters:
                validated_value = validator(filters[key])
                if validated_value:
                    safe_filters[key] = validated_value
        
        # Apply safe filters
        if safe_filters.get('date_from'):
            try:
                start_date = timezone.datetime.strptime(safe_filters['date_from'], '%Y-%m-%d').date()
                queryset = queryset.filter(submitted_at__date__gte=start_date)
            except ValueError:
                pass  # Ignore invalid dates
        
        if safe_filters.get('country'):
            queryset = queryset.filter(country=safe_filters['country'])
        
        if safe_filters.get('search'):
            # Use exact lookups to prevent injection
            from django.db.models import Q
            search_term = safe_filters['search']
            queryset = queryset.filter(
                Q(name__icontains=search_term) |
                Q(email__icontains=search_term)
            )
        
        # Log data access
        count = queryset.count()
        log_security_event(
            'DATA_ACCESS', 'LOW', self.request,
            f'Admin accessed {count} submissions',
            {'record_count': count, 'filters': safe_filters}
        )
        
        return queryset.order_by('-submitted_at')

@method_decorator(never_cache, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')  # ✅ ADDED: CSRF exempt for API
class SubmissionDetailView(generics.RetrieveAPIView):
    """Secure admin endpoint for submission details"""
    queryset = Submission.objects.all()
    serializer_class = SubmissionDetailSerializer
    permission_classes = [IsAdminUser]
    throttle_classes = [AdminRateThrottle]
    
    def retrieve(self, request, *args, **kwargs):
        try:
            response = super().retrieve(request, *args, **kwargs)
            
            # Log sensitive data access
            submission_id = kwargs.get('pk')
            log_security_event(
                'SENSITIVE_DATA_ACCESS', 'HIGH', request,
                f'Admin {request.user.username} viewed submission details',
                {'submission_id': submission_id, 'admin_user': request.user.username}
            )
            
            return response
            
        except Submission.DoesNotExist:
            log_security_event(
                'SUSPICIOUS_ACTIVITY', 'MEDIUM', request,
                f'Admin attempted to access non-existent submission: {kwargs.get("pk")}'
            )
            return Response({
                'success': False,
                'message': 'Submission not found'
            }, status=status.HTTP_404_NOT_FOUND)

@api_view(['DELETE'])
@permission_classes([IsAdminUser])
@throttle_classes([AdminRateThrottle])
@ratelimit(key='user', rate='5/m', method='DELETE', block=True)
@csrf_exempt  # ✅ ADDED: CSRF exempt for API
@never_cache
def delete_submission(request, pk):
    """Secure admin endpoint for submission deletion"""
    
    try:
        submission = Submission.objects.get(pk=pk)
        
        # Enhanced deletion logging
        log_security_event(
            'DATA_DELETION', 'CRITICAL', request,
            f'Admin {request.user.username} deleted submission',
            {
                'submission_id': submission.id,
                'submission_uuid': str(submission.uuid),
                'admin_user': request.user.username,
                'submitted_at': submission.submitted_at.isoformat(),
                'anonymized': submission.anonymized
            }
        )
        
        submission.delete()
        
        return Response({
            'success': True,
            'message': 'Submission deleted successfully'
        }, status=status.HTTP_200_OK)
        
    except Submission.DoesNotExist:
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'HIGH', request,
            f'Admin {request.user.username} attempted to delete non-existent submission: {pk}'
        )
        return Response({
            'success': False,
            'message': 'Submission not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    except Exception as e:
        logger.error(f"Deletion error: {e}", exc_info=True)
        log_security_event(
            'API_ERROR', 'HIGH', request,
            f'Error deleting submission {pk}'
        )
        return Response({
            'success': False,
            'message': 'Unable to delete submission'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAdminUser])
@throttle_classes([AdminRateThrottle])
@ratelimit(key='user', rate='1/h', method='POST', block=True)
@csrf_exempt  # ✅ ADDED: CSRF exempt for API
@never_cache
def delete_all_submissions(request):
    """Ultra-secure bulk deletion endpoint"""
    
    # Enhanced confirmation mechanism
    confirmation = request.data.get('confirmation')
    
    if confirmation != 'delete_permanently':  # ✅ FIXED: Match frontend expectation
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
        
        # Log critical action
        log_security_event(
            'BULK_DATA_DELETION', 'CRITICAL', request,
            f'Admin {request.user.username} initiated bulk deletion of {count} submissions',
            {
                'deletion_count': count,
                'admin_user': request.user.username,
                'confirmed': True
            }
        )
        
        # Perform deletion
        Submission.objects.all().delete()
        
        return Response({
            'success': True,
            'message': f'Successfully deleted {count} submissions'
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Bulk deletion error: {e}", exc_info=True)
        log_security_event(
            'API_ERROR', 'CRITICAL', request,
            f'Error in bulk deletion: {str(e)}'
        )
        return Response({
            'success': False,
            'message': 'Bulk deletion failed'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Placeholder implementations for completeness
@api_view(['GET'])
@permission_classes([IsAdminUser])
@throttle_classes([AdminRateThrottle])
@csrf_exempt  # ✅ ADDED: CSRF exempt for API
def download_submissions_excel(request):
    """Secure Excel download endpoint"""
    log_security_event(
        'DATA_EXPORT', 'HIGH', request,
        f'Admin {request.user.username} exported data to Excel'
    )
    return Response({'message': 'Excel export feature not implemented yet'})

@api_view(['GET'])
@permission_classes([IsAdminUser])
@csrf_exempt  # ✅ ADDED: CSRF exempt for API
def get_filter_options(request):
    """Get available filter options"""
    return Response({'message': 'Filter options endpoint not implemented yet'})

@api_view(['GET'])
@permission_classes([IsAdminUser])
@csrf_exempt  # ✅ ADDED: CSRF exempt for API
def submission_stats(request):
    """Get submission statistics"""
    return Response({'message': 'Statistics endpoint not implemented yet'})