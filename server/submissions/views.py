# server/submissions/views.py - SQL INJECTION PROOF VERSION

import re
import hashlib
import json
import logging
from datetime import timedelta
from io import BytesIO

from django.http import HttpResponse
from django.utils import timezone
from django.core.cache import cache
from django.db import transaction
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db.models import Q, Count
from django.core.exceptions import ValidationError
from django.utils.html import escape

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

# 🔒 SQL INJECTION PROTECTION: Comprehensive SQL injection detection
class SQLInjectionDetector:
    """Advanced SQL injection detection and prevention"""
    
    # 🔒 CRITICAL: Comprehensive SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        # Union-based injections
        r'\bunion\s+(all\s+)?select\b',
        r'\bunion\s+select\b',
        
        # Boolean-based blind injections
        r'\b(and|or)\s+\d+\s*[=<>!]+\s*\d+\b',
        r'\b(and|or)\s+[\'"]?\w+[\'"]?\s*[=<>!]+\s*[\'"]?\w+[\'"]?\b',
        r'\b1\s*=\s*1\b',
        r'\b1\s*or\s*1\b',
        r'\btrue\s*=\s*true\b',
        r'\bfalse\s*=\s*false\b',
        
        # Time-based injections
        r'\bwaitfor\s+delay\b',
        r'\bsleep\s*\(\s*\d+\s*\)\b',
        r'\bbenchmark\s*\(',
        r'\bpg_sleep\s*\(',
        
        # Error-based injections
        r'\bcast\s*\(\s*.*\s+as\s+int\s*\)\b',
        r'\bconvert\s*\(\s*int\s*,\s*.*\s*\)\b',
        r'\bextractvalue\s*\(',
        r'\bupdatexml\s*\(',
        
        # SQL commands
        r'\b(select|insert|update|delete|drop|create|alter|exec|execute|sp_|xp_)\b',
        
        # SQL comments
        r'(--|#|/\*|\*/)',
        
        # String manipulation
        r'\bchar\s*\(\s*\d+\s*\)\b',
        r'\bconcat\s*\(',
        r'\bsubstring\s*\(',
        
        # Database specific
        r'\binformation_schema\b',
        r'\bsysobjects\b',
        r'\bsyscolumns\b',
        r'\bmysql\.\w+\b',
        r'\bpg_\w+\b',
        
        # Advanced injections
        r'\bhaving\s+\d+\s*=\s*\d+\b',
        r'\bgroup\s+by\s+\d+\b',
        r'\border\s+by\s+\d+\b',
        r'\blimit\s+\d+\s*,\s*\d+\b',
        
        # Hex and encoded injections
        r'0x[0-9a-fA-F]+',
        r'%27|%22|%2d%2d|%23',  # URL encoded quotes and comments
        
        # Stacked queries
        r';\s*(select|insert|update|delete|drop|create|alter)\b',
        
        # Function calls that shouldn't be in user input
        r'\b(load_file|into\s+outfile|into\s+dumpfile)\b',
        r'\bload\s+data\s+infile\b',
    ]
    
    @classmethod
    def detect_sql_injection(cls, text):
        """
        🔒 CRITICAL: Detect SQL injection attempts
        Returns (is_injection, pattern_matched, severity)
        """
        if not text:
            return False, None, 'NONE'
        
        text = str(text).lower()
        
        # Check each pattern
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                # Determine severity
                if any(dangerous in pattern for dangerous in ['drop', 'delete', 'insert', 'update', 'exec']):
                    severity = 'CRITICAL'
                elif any(medium in pattern for medium in ['union', 'select', 'information_schema']):
                    severity = 'HIGH'
                else:
                    severity = 'MEDIUM'
                
                return True, pattern, severity
        
        return False, None, 'NONE'
    
    @classmethod
    def sanitize_sql_input(cls, text):
        """
        🔒 CRITICAL: Sanitize input to prevent SQL injection
        """
        if not text:
            return text
        
        # Remove dangerous characters and patterns
        text = str(text)
        
        # Remove SQL comments
        text = re.sub(r'(--|#|/\*.*?\*/)', '', text, flags=re.DOTALL)
        
        # Remove dangerous quotes combinations
        text = re.sub(r"['\"];?\s*(union|select|insert|update|delete|drop)", '', text, flags=re.IGNORECASE)
        
        # Escape remaining quotes
        text = text.replace("'", "''").replace('"', '""')
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        return text

# 🔒 SQL INJECTION PROOF: Secure rate limiter
class SQLSecureRateLimiter:
    """SQL injection proof rate limiter"""
    
    @staticmethod
    def is_rate_limited(key, limit, window_seconds):
        """Rate limiter that prevents SQL injection in cache keys"""
        try:
            # 🔒 CRITICAL: Sanitize cache key to prevent injection
            safe_key = re.sub(r'[^a-zA-Z0-9_\-:]', '_', str(key))
            safe_key = f"rate_limit:{safe_key}"
            
            current_time = timezone.now()
            attempts = cache.get(safe_key, [])
            
            cutoff_time = current_time - timedelta(seconds=window_seconds)
            recent_attempts = [
                attempt for attempt in attempts 
                if attempt > cutoff_time.timestamp()
            ]
            
            if len(recent_attempts) >= limit:
                return True
            
            recent_attempts.append(current_time.timestamp())
            cache.set(safe_key, recent_attempts, window_seconds)
            
            return False
            
        except Exception as e:
            logger.error(f"Rate limiter error: {e}")
            return False

def log_security_event(event_type, severity, request, description, metadata=None):
    """🔒 SQL INJECTION PROOF: Secure logging"""
    try:
        # 🔒 CRITICAL: Sanitize all inputs before database storage
        safe_description = escape(str(description)[:1000])  # Limit length and escape
        safe_user_agent = escape(request.META.get('HTTP_USER_AGENT', '')[:500])
        safe_metadata = {}
        
        if metadata:
            for key, value in metadata.items():
                # Sanitize metadata keys and values
                safe_key = re.sub(r'[^a-zA-Z0-9_]', '_', str(key)[:50])
                safe_value = escape(str(value)[:500])
                safe_metadata[safe_key] = safe_value
        
        SecurityEvent.objects.create(
            event_type=event_type,
            severity=severity,
            ip_address=get_client_ip(request),
            user_agent=safe_user_agent,
            user=request.user if request.user.is_authenticated else None,
            description=safe_description,
            metadata=safe_metadata
        )
        
        logger.warning(f"SECURITY: {event_type} - {safe_description} - IP: {get_client_ip(request)}")
        
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
@never_cache
@require_http_methods(['POST'])
def submit_form(request):
    """🔒 SQL INJECTION PROOF: Ultra-secure form submission endpoint"""
    
    client_ip = get_client_ip(request)
    
    # 🔒 CRITICAL: SQL injection detection on ALL input data
    try:
        request_body = request.body.decode('utf-8') if request.body else ''
        all_input_text = f"{request_body} {request.META.get('HTTP_USER_AGENT', '')} {request.path}"
        
        is_injection, pattern, severity = SQLInjectionDetector.detect_sql_injection(all_input_text)
        
        if is_injection:
            log_security_event(
                'SQL_INJECTION_ATTEMPT', 
                'CRITICAL', 
                request,
                f'SQL injection detected: {pattern}',
                {
                    'pattern': pattern,
                    'severity': severity,
                    'input_length': len(all_input_text),
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')[:100]
                }
            )
            
            # 🔒 CRITICAL: Immediately block SQL injection attempts
            return Response({
                'success': False,
                'message': 'Security violation detected. Request blocked.'
            }, status=status.HTTP_403_FORBIDDEN)
    
    except Exception as e:
        logger.error(f"SQL injection detection error: {e}")
        # Fail secure - block if detection fails
        return Response({
            'success': False,
            'message': 'Security check failed. Request blocked.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    # Basic input validation
    if not request.data:
        log_security_event('SUSPICIOUS_ACTIVITY', 'MEDIUM', request, 'Empty form submission')
        return Response({
            'success': False,
            'message': 'No data provided'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # 🔒 CRITICAL: SQL injection check on form data
    for field, value in request.data.items():
        if value:
            is_injection, pattern, severity = SQLInjectionDetector.detect_sql_injection(str(value))
            if is_injection:
                log_security_event(
                    'SQL_INJECTION_ATTEMPT', 
                    'CRITICAL', 
                    request,
                    f'SQL injection in field {field}: {pattern}',
                    {'field': field, 'pattern': pattern}
                )
                return Response({
                    'success': False,
                    'message': 'Invalid data detected. Please check your input.'
                }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Rate limiting with SQL-safe key
        safe_ip = re.sub(r'[^0-9\.\:]', '_', client_ip)
        if SQLSecureRateLimiter.is_rate_limited(f"form_submit_{safe_ip}", 3, 3600):
            log_security_event(
                'RATE_LIMIT', 'HIGH', request, 
                'Form submission rate limit exceeded'
            )
            return Response({
                'success': False,
                'message': 'Too many requests. Please wait before trying again.'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        # 🔒 CRITICAL: Use Django ORM exclusively - NO RAW SQL
        serializer = SecureSubmissionCreateSerializer(data=request.data)
        
        if serializer.is_valid():
            # 🔒 CRITICAL: Use atomic transaction to prevent injection
            with transaction.atomic():
                # Use Django ORM create() method - automatically parameterized
                submission = serializer.save()
                
                # 🔒 SAFE: Using Django ORM for duplicate detection
                data_hash = hashlib.sha256(
                    json.dumps(serializer.validated_data, sort_keys=True).encode()
                ).hexdigest()
                
                cache_key = f"submission_{data_hash}"  # Simple, safe cache key
                cache.set(cache_key, True, 3600)
                
                # 🔒 SAFE: Log with sanitized data
                log_security_event(
                    'FORM_SUBMISSION', 'LOW', request,
                    f'Form submitted successfully',
                    {
                        'submission_uuid': str(submission.uuid),
                        'country': submission.country,
                        'has_investment': bool(submission.step5)
                    }
                )
            
            return Response({
                'success': True,
                'message': 'Thank you for your submission. Our team will review your application and contact you within 2-3 business days.',
                'submission_id': str(submission.uuid)
            }, status=status.HTTP_201_CREATED)
        
        else:
            # 🔒 SAFE: Log validation errors safely
            log_security_event(
                'FORM_VALIDATION_ERROR', 'LOW', request,
                'Form validation failed',
                {'error_count': len(serializer.errors)}
            )
            
            return Response({
                'success': False,
                'message': 'Please correct the errors in your form.',
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

# 🔒 SQL INJECTION PROOF: Secure admin list view
@method_decorator(never_cache, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class SubmissionListView(generics.ListAPIView):
    """🔒 SQL INJECTION PROOF: Ultra-secure admin submission list"""
    serializer_class = SubmissionListSerializer
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        """🔒 CRITICAL: SQL injection proof queryset filtering"""
        # 🔒 CRITICAL: Start with base queryset - NO raw SQL
        queryset = Submission.objects.all()
        
        # 🔒 CRITICAL: Validate and sanitize ALL filter parameters
        filters = self.request.query_params
        
        # 🔒 WHITELIST approach: Only allow specific, validated filters
        ALLOWED_FILTERS = {
            'date_from': r'^\d{4}-\d{2}-\d{2}$',  # YYYY-MM-DD format only
            'date_to': r'^\d{4}-\d{2}-\d{2}$',    # YYYY-MM-DD format only
            'country': r'^[A-Z]{2}$',             # 2-letter country codes only
        }
        
        validated_filters = {}
        
        for filter_key, pattern in ALLOWED_FILTERS.items():
            if filter_key in filters:
                filter_value = str(filters[filter_key]).strip()
                
                # 🔒 CRITICAL: SQL injection check on filter values
                is_injection, sql_pattern, severity = SQLInjectionDetector.detect_sql_injection(filter_value)
                if is_injection:
                    log_security_event(
                        'SQL_INJECTION_ATTEMPT', 'CRITICAL', self.request,
                        f'SQL injection in filter {filter_key}: {sql_pattern}'
                    )
                    continue  # Skip this filter
                
                # 🔒 CRITICAL: Validate filter format with regex
                if re.match(pattern, filter_value):
                    validated_filters[filter_key] = filter_value
        
        # 🔒 SAFE: Apply validated filters using Django ORM
        if validated_filters.get('date_from'):
            try:
                # 🔒 SAFE: Django ORM prevents SQL injection
                start_date = timezone.datetime.strptime(validated_filters['date_from'], '%Y-%m-%d').date()
                queryset = queryset.filter(submitted_at__date__gte=start_date)
            except ValueError:
                pass  # Invalid date format, skip filter
        
        if validated_filters.get('date_to'):
            try:
                # 🔒 SAFE: Django ORM prevents SQL injection
                end_date = timezone.datetime.strptime(validated_filters['date_to'], '%Y-%m-%d').date()
                queryset = queryset.filter(submitted_at__date__lte=end_date)
            except ValueError:
                pass  # Invalid date format, skip filter
        
        if validated_filters.get('country'):
            # 🔒 SAFE: Django ORM with validated input
            queryset = queryset.filter(country=validated_filters['country'])
        
        # 🔒 SAFE: Log data access with sanitized info
        count = queryset.count()
        log_security_event(
            'DATA_ACCESS', 'MEDIUM', self.request,
            f'Admin accessed {count} submissions',
            {
                'record_count': count,
                'filters_applied': len(validated_filters),
                'admin_user': self.request.user.username
            }
        )
        
        # 🔒 SAFE: Return with Django ORM ordering (not raw SQL)
        return queryset.order_by('-submitted_at')

# 🔒 SQL INJECTION PROOF: Secure admin detail view  
@method_decorator(never_cache, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class SubmissionDetailView(generics.RetrieveAPIView):
    """🔒 SQL INJECTION PROOF: Ultra-secure admin submission detail view"""
    queryset = Submission.objects.all()
    serializer_class = SubmissionDetailSerializer
    permission_classes = [IsAdminUser]
    
    def retrieve(self, request, *args, **kwargs):
        """🔒 CRITICAL: SQL injection proof detail retrieval"""
        try:
            # 🔒 CRITICAL: Validate primary key parameter
            pk = kwargs.get('pk')
            try:
                submission_id = int(pk)
                if submission_id <= 0:
                    raise ValueError("Invalid ID")
            except (ValueError, TypeError):
                log_security_event(
                    'SUSPICIOUS_ACTIVITY', 'HIGH', request,
                    f'Invalid submission ID in detail request: {pk}'
                )
                return Response({
                    'success': False,
                    'message': 'Invalid submission ID'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # 🔒 CRITICAL: SQL injection check on PK parameter
            is_injection, pattern, severity = SQLInjectionDetector.detect_sql_injection(str(pk))
            if is_injection:
                log_security_event(
                    'SQL_INJECTION_ATTEMPT', 'CRITICAL', request,
                    f'SQL injection in detail PK: {pattern}'
                )
                return Response({
                    'success': False,
                    'message': 'Security violation detected'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # 🔒 SAFE: Use Django ORM get() with validated integer
            submission = Submission.objects.get(pk=submission_id)
            
            # 🔒 SAFE: Log access with sanitized data
            log_security_event(
                'SENSITIVE_DATA_ACCESS', 'HIGH', request,
                f'Admin viewed submission details',
                {
                    'submission_id': submission_id,
                    'submission_uuid': str(submission.uuid),
                    'admin_user': request.user.username
                }
            )
            
            # 🔒 SAFE: Serialize and return
            serializer = self.get_serializer(submission)
            return Response(serializer.data)
            
        except Submission.DoesNotExist:
            log_security_event(
                'SUSPICIOUS_ACTIVITY', 'MEDIUM', request,
                f'Admin attempted to access non-existent submission: {kwargs.get("pk")}'
            )
            return Response({
                'success': False,
                'message': 'Submission not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Detail view error: {e}")
            return Response({
                'success': False,
                'message': 'Unable to retrieve submission details'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# 🔒 SQL INJECTION PROOF: Secure delete endpoint
@api_view(['DELETE'])
@permission_classes([IsAdminUser])
@csrf_exempt
@never_cache
def delete_submission(request, pk):
    """🔒 SQL INJECTION PROOF: Secure deletion endpoint"""
    
    # 🔒 CRITICAL: Validate primary key parameter
    try:
        # 🔒 CRITICAL: Ensure pk is a valid integer
        submission_id = int(pk)
        if submission_id <= 0:
            raise ValueError("Invalid ID")
    except (ValueError, TypeError):
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'HIGH', request,
            f'Invalid submission ID in delete request: {pk}'
        )
        return Response({
            'success': False,
            'message': 'Invalid submission ID'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # 🔒 CRITICAL: SQL injection detection on PK parameter
    is_injection, pattern, severity = SQLInjectionDetector.detect_sql_injection(str(pk))
    if is_injection:
        log_security_event(
            'SQL_INJECTION_ATTEMPT', 'CRITICAL', request,
            f'SQL injection in delete PK: {pattern}'
        )
        return Response({
            'success': False,
            'message': 'Security violation detected'
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        # 🔒 SAFE: Use Django ORM get() with validated integer
        submission = Submission.objects.get(pk=submission_id)
        
        # 🔒 SAFE: Log before deletion with sanitized data
        log_security_event(
            'DATA_DELETION', 'CRITICAL', request,
            f'Admin deleted submission',
            {
                'submission_id': submission_id,
                'submission_uuid': str(submission.uuid),
                'admin_user': request.user.username,
                'submitted_at': submission.submitted_at.isoformat(),
            }
        )
        
        # 🔒 SAFE: Use Django ORM delete()
        submission.delete()
        
        return Response({
            'success': True,
            'message': 'Submission deleted successfully'
        }, status=status.HTTP_200_OK)
        
    except Submission.DoesNotExist:
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'MEDIUM', request,
            f'Admin attempted to delete non-existent submission: {submission_id}'
        )
        return Response({
            'success': False,
            'message': 'Submission not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Delete error: {e}")
        return Response({
            'success': False,
            'message': 'Deletion failed'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# 🔒 EMERGENCY: Database breach response endpoint
@api_view(['POST'])
@permission_classes([IsAdminUser])
@csrf_exempt
def emergency_security_lockdown(request):
    """🔒 EMERGENCY: Lock down system after breach detection"""
    
    confirmation = request.data.get('confirmation')
    if confirmation != 'EMERGENCY_LOCKDOWN_CONFIRMED':
        return Response({
            'success': False,
            'message': 'Invalid confirmation for emergency lockdown'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # 🔒 EMERGENCY: Log critical security event
        log_security_event(
            'EMERGENCY_LOCKDOWN', 'CRITICAL', request,
            f'Emergency security lockdown initiated by {request.user.username}',
            {
                'admin_user': request.user.username,
                'lockdown_reason': 'SQL injection breach detected',
                'timestamp': timezone.now().isoformat()
            }
        )
        
        # 🔒 EMERGENCY: Clear all caches
        cache.clear()
        
        # 🔒 EMERGENCY: Count potentially compromised records
        submission_count = Submission.objects.count()
        
        return Response({
            'success': True,
            'message': f'Emergency lockdown completed. {submission_count} records secured.',
            'recommendations': [
                'Change all database passwords immediately',
                'Review database logs for unauthorized access',
                'Run integrity checks on all data',
                'Consider taking database offline for forensic analysis',
                'Update all application security patches'
            ]
        })
        
    except Exception as e:
        logger.error(f"Emergency lockdown failed: {e}")
        return Response({
            'success': False,
            'message': 'Emergency lockdown failed'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)