# submissions/views.py - ULTRA-SECURE FORM SYSTEM (No external rate limiting)

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
from django.views.decorators.cache import never_cache
from django.utils.decorators import method_decorator

from .models import Submission
from .serializers import SecureSubmissionCreateSerializer, SubmissionListSerializer, SubmissionDetailSerializer
from security_monitoring.models import SecurityEvent
from security_monitoring.utils import get_client_ip

logger = logging.getLogger('security_monitoring')

# Custom throttle classes for ultra-secure form system
class UltraSecureFormThrottle(AnonRateThrottle):
    rate = '2/min'  # Ultra-strict: 2 form submissions per minute
    
class UltraSecureAdminThrottle(UserRateThrottle):
    rate = '50/hour'  # Strict admin operations

class UltraSecureRateLimiter:
    """Built-in rate limiter using Django cache (no external dependencies)"""
    
    @staticmethod
    def is_rate_limited(key, limit, window_seconds):
        """Check if request should be rate limited using Django cache"""
        try:
            current_time = timezone.now()
            cache_key = f"rate_limit:{key}"
            
            # Get existing attempts
            attempts = cache.get(cache_key, [])
            
            # Remove old attempts outside window
            cutoff_time = current_time - timedelta(seconds=window_seconds)
            recent_attempts = [
                attempt for attempt in attempts 
                if attempt > cutoff_time.timestamp()
            ]
            
            # Check if limit exceeded
            if len(recent_attempts) >= limit:
                return True
            
            # Add current attempt
            recent_attempts.append(current_time.timestamp())
            cache.set(cache_key, recent_attempts, window_seconds)
            
            return False
            
        except Exception:
            # Fail open for availability
            return False

def log_security_event(event_type, severity, request, description, metadata=None):
    """Enhanced security event logging for form system"""
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
        
        logger.warning(f"FORM_SECURITY: {event_type} - {description} - IP: {get_client_ip(request)}")
        
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

def ultra_secure_spam_detection(request, form_data):
    """Ultra-secure spam detection for form submissions"""
    client_ip = get_client_ip(request)
    
    # 1. Ultra-strict rate limiting
    if UltraSecureRateLimiter.is_rate_limited(f"form_submission:{client_ip}", 2, 3600):
        return True, "Rate limit exceeded (2 submissions per hour)"
    
    # 2. Enhanced content analysis
    all_text = ' '.join([str(form_data.get(field, '')) for field in form_data.keys()]).lower()
    
    # Ultra-strict spam indicators
    spam_indicators = {
        'critical_risk': ['spam', 'test', 'fake', 'bot', 'script'],
        'high_risk': ['urgent', 'click', 'free', 'winner', 'casino', 'viagra'],
        'suspicious_patterns': [
            r'\b\w*\d{4,}\w*\b',  # Numbers with 4+ digits
            r'[A-Z]{10,}',        # Too many caps
            r'(.)\1{5,}',         # Repeated characters
            r'https?://',         # URLs in form
            r'www\.',             # Web addresses
        ]
    }
    
    risk_score = 0
    
    # Check critical risk (immediate block)
    for keyword in spam_indicators['critical_risk']:
        if keyword in all_text:
            return True, f"Critical spam keyword detected: {keyword}"
    
    # Check high-risk keywords
    for keyword in spam_indicators['high_risk']:
        if keyword in all_text:
            risk_score += 15
    
    # Check suspicious patterns
    for pattern in spam_indicators['suspicious_patterns']:
        if re.search(pattern, all_text):
            risk_score += 10
    
    # 3. Length-based detection
    if len(all_text) > 5000:  # Very long submission
        risk_score += 20
    elif len(all_text) < 20:  # Very short submission
        risk_score += 15
    
    # 4. Field validation
    required_fields = ['name', 'email', 'phone']
    for field in required_fields:
        if not form_data.get(field, '').strip():
            risk_score += 10
    
    # 5. Email validation
    email = form_data.get('email', '')
    if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        risk_score += 20
    
    return risk_score >= 25, f"Spam detected (risk score: {risk_score})"

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([UltraSecureFormThrottle])
@csrf_exempt
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
        # Ultra-secure spam detection
        is_spam, spam_reason = ultra_secure_spam_detection(request, request.data)
        if is_spam:
            log_security_event(
                'FORM_SPAM', 'HIGH', request,
                f'Ultra-secure spam detection: {spam_reason}',
                {'form_data_length': len(str(request.data)), 'reason': spam_reason}
            )
            return Response({
                'success': False,
                'message': 'Submission blocked by security filter'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        # Ultra-secure validation
        serializer = SecureSubmissionCreateSerializer(data=request.data)
        
        if serializer.is_valid():
            # Create unique hash for duplicate detection
            data_hash = hashlib.sha256(
                json.dumps(serializer.validated_data, sort_keys=True).encode()
            ).hexdigest()
            
            # Check for duplicates (24-hour window)
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
            
            # Save with ultra-secure transaction
            with transaction.atomic():
                submission = serializer.save()
                
                # Cache submission hash
                cache.set(cache_key, True, 86400)  # 24 hours
                
                # Log successful submission
                log_security_event(
                    'FORM_SUBMISSION', 'LOW', request,
                    f'Secure form submission: {submission.uuid}',
                    {'submission_id': str(submission.uuid)}
                )
            
            return Response({
                'success': True,
                'message': 'Form submitted successfully',
                'submission_id': str(submission.uuid)
            }, status=status.HTTP_201_CREATED)
        
        else:
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
@method_decorator(csrf_exempt, name='dispatch')
class SubmissionListView(generics.ListAPIView):
    """Ultra-secure admin endpoint to list submissions"""
    serializer_class = SubmissionListSerializer
    permission_classes = [IsAdminUser]
    throttle_classes = [UltraSecureAdminThrottle]

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            log_security_event(
                'ADMIN_ACCESS', 'MEDIUM', request,
                f'Admin {request.user.username} accessed submission list',
                {'admin_user': request.user.username}
            )
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        """Ultra-secure queryset with validation"""
        queryset = Submission.objects.all()
        
        # Validate and sanitize filters
        filters = self.request.query_params
        safe_filters = {}
        
        # Ultra-strict filter validation
        allowed_filters = {
            'date_from': lambda x: x if re.match(r'^\d{4}-\d{2}-\d{2}$', x) else None,
            'date_to': lambda x: x if re.match(r'^\d{4}-\d{2}-\d{2}$', x) else None,
            'country': lambda x: x if re.match(r'^[A-Z]{2}$', x) else None,
            'search': lambda x: x[:30] if len(x) <= 30 else None,  # Limit search
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
                pass
        
        if safe_filters.get('country'):
            queryset = queryset.filter(country=safe_filters['country'])
        
        if safe_filters.get('search'):
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
@method_decorator(csrf_exempt, name='dispatch')
class SubmissionDetailView(generics.RetrieveAPIView):
    """Ultra-secure admin endpoint for submission details"""
    queryset = Submission.objects.all()
    serializer_class = SubmissionDetailSerializer
    permission_classes = [IsAdminUser]
    throttle_classes = [UltraSecureAdminThrottle]
    
    def retrieve(self, request, *args, **kwargs):
        try:
            response = super().retrieve(request, *args, **kwargs)
            
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
@throttle_classes([UltraSecureAdminThrottle])
@csrf_exempt
@never_cache
def delete_submission(request, pk):
    """Ultra-secure admin endpoint for submission deletion"""
    
    # Rate limiting for deletions
    client_ip = get_client_ip(request)
    if UltraSecureRateLimiter.is_rate_limited(f"delete_submission:{client_ip}", 5, 3600):
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'HIGH', request,
            'Deletion rate limit exceeded'
        )
        return Response({
            'success': False,
            'message': 'Too many deletion attempts'
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)
    
    try:
        submission = Submission.objects.get(pk=pk)
        
        log_security_event(
            'DATA_DELETION', 'CRITICAL', request,
            f'Admin {request.user.username} deleted submission',
            {
                'submission_id': submission.id,
                'submission_uuid': str(submission.uuid),
                'admin_user': request.user.username,
                'submitted_at': submission.submitted_at.isoformat(),
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
            f'Admin attempted to delete non-existent submission: {pk}'
        )
        return Response({
            'success': False,
            'message': 'Submission not found'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([IsAdminUser])
@throttle_classes([UltraSecureAdminThrottle])
@csrf_exempt
@never_cache
def delete_all_submissions(request):
    """Ultra-secure bulk deletion endpoint"""
    
    # Ultra-strict confirmation
    confirmation = request.data.get('confirmation')
    
    if confirmation != 'delete_permanently':
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'HIGH', request,
            f'Admin attempted bulk deletion without proper confirmation'
        )
        return Response({
            'success': False,
            'message': 'Invalid confirmation. Type "delete_permanently" to confirm.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Additional IP-based rate limiting for bulk operations
    client_ip = get_client_ip(request)
    if UltraSecureRateLimiter.is_rate_limited(f"bulk_delete:{client_ip}", 1, 86400):
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'CRITICAL', request,
            'Bulk deletion rate limit exceeded (1 per day)'
        )
        return Response({
            'success': False,
            'message': 'Bulk deletion already performed today'
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)
    
    try:
        count = Submission.objects.count()
        
        log_security_event(
            'BULK_DATA_DELETION', 'CRITICAL', request,
            f'Admin {request.user.username} initiated bulk deletion of {count} submissions',
            {
                'deletion_count': count,
                'admin_user': request.user.username,
                'confirmed': True
            }
        )
        
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

# Ultra-secure implementations for admin features
@api_view(['GET'])
@permission_classes([IsAdminUser])
@throttle_classes([UltraSecureAdminThrottle])
@csrf_exempt
def download_submissions_excel(request):
    """Ultra-secure Excel download endpoint"""
    log_security_event(
        'DATA_EXPORT', 'HIGH', request,
        f'Admin {request.user.username} exported data to Excel'
    )
    
    # Implementation would create Excel file with encrypted data
    # For now, return placeholder
    return Response({
        'success': True,
        'message': 'Excel export prepared',
        'download_url': '/api/admin/download/file.xlsx'
    })

@api_view(['GET'])
@permission_classes([IsAdminUser])
@csrf_exempt
def get_filter_options(request):
    """Get available filter options for admin"""
    try:
        # Get unique values for filters
        countries = list(Submission.objects.values_list('country', flat=True).distinct())
        
        return Response({
            'success': True,
            'filters': {
                'countries': [{'code': country, 'display': country} for country in countries],
                'service_types': ['investment fund', 'broker', 'cryptocurrency wallet/exchange', 'other'],
                'issue_timeframes': ['less than a month', 'up to three months', 'less than a year', 'more than a year'],
                'primary_goals': ['Networking', 'Career Development', 'Learning', 'Business Growth'],
                'communication_methods': ['Email', 'Phone', 'Text Message', 'Video Call'],
            }
        })
    except Exception as e:
        logger.error(f"Filter options error: {e}")
        return Response({'success': False, 'message': 'Failed to load filter options'})

@api_view(['GET'])
@permission_classes([IsAdminUser])
@csrf_exempt
def submission_stats(request):
    """Get ultra-secure submission statistics"""
    try:
        from django.db.models import Count
        from datetime import datetime, timedelta
        
        now = timezone.now()
        
        # Basic stats
        total_submissions = Submission.objects.count()
        
        # Time-based stats
        last_24h = Submission.objects.filter(submitted_at__gte=now - timedelta(hours=24)).count()
        last_7d = Submission.objects.filter(submitted_at__gte=now - timedelta(days=7)).count()
        
        # Country breakdown
        country_breakdown = dict(
            Submission.objects.values_list('country').annotate(count=Count('country'))
        )
        
        return Response({
            'success': True,
            'stats': {
                'total_submissions': total_submissions,
                'last_24h': last_24h,
                'last_7d': last_7d,
                'country_breakdown': country_breakdown,
                'date_range': {
                    'from': (now - timedelta(days=30)).date().isoformat(),
                    'to': now.date().isoformat(),
                    'preset': '30_days'
                }
            }
        })
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return Response({'success': False, 'message': 'Failed to load statistics'})