# security_monitoring/api_security.py - Advanced API security
import re
import time
import hmac
import hashlib
import json
from datetime import datetime, timedelta
from django.core.cache import cache
from django.conf import settings
from django.http import JsonResponse
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from .models import SecurityEvent

class APISecurityValidator:
    """Advanced API security validation"""
    
    def __init__(self):
        self.max_payload_size = 1024 * 1024  # 1MB
        self.request_timeout = 30  # seconds
        
    def validate_request_signature(self, request, secret_key):
        """Validate HMAC signature for API requests"""
        received_signature = request.headers.get('X-Signature')
        if not received_signature:
            return False
        
        # Get request body
        payload = request.body
        expected_signature = hmac.new(
            secret_key.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(received_signature, expected_signature)
    
    def validate_timestamp(self, timestamp, tolerance=300):
        """Validate request timestamp to prevent replay attacks"""
        try:
            request_time = datetime.fromtimestamp(float(timestamp))
            current_time = datetime.now()
            time_diff = abs((current_time - request_time).total_seconds())
            return time_diff <= tolerance
        except (ValueError, TypeError):
            return False
    
    def validate_nonce(self, nonce, window=3600):
        """Validate nonce to prevent replay attacks"""
        cache_key = f"nonce:{nonce}"
        if cache.get(cache_key):
            return False  # Nonce already used
        
        cache.set(cache_key, True, window)
        return True
    
    def validate_payload_size(self, request):
        """Validate payload size"""
        content_length = request.META.get('CONTENT_LENGTH')
        if content_length:
            try:
                size = int(content_length)
                return size <= self.max_payload_size
            except ValueError:
                return False
        return True
    
    def detect_api_abuse(self, request, endpoint):
        """Detect API abuse patterns"""
        client_ip = self.get_client_ip(request)
        
        # Check for rapid successive requests
        rapid_key = f"rapid_requests:{client_ip}:{endpoint}"
        recent_requests = cache.get(rapid_key, 0)
        
        if recent_requests > 10:  # More than 10 requests in short time
            return True, "Rapid successive requests detected"
        
        cache.set(rapid_key, recent_requests + 1, 60)  # 1 minute window
        
        # Check for unusual request patterns
        pattern_key = f"request_pattern:{client_ip}"
        patterns = cache.get(pattern_key, {})
        patterns[endpoint] = patterns.get(endpoint, 0) + 1
        
        # If hitting too many different endpoints rapidly
        if len(patterns) > 5 and sum(patterns.values()) > 20:
            return True, "Suspicious endpoint scanning detected"
        
        cache.set(pattern_key, patterns, 3600)  # 1 hour window
        return False, ""
    
    def get_client_ip(self, request):
        """Get real client IP"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

class APIRateLimiter:
    """Advanced rate limiting with different strategies"""
    
    def __init__(self):
        self.algorithms = {
            'token_bucket': self.token_bucket_limit,
            'sliding_window': self.sliding_window_limit,
            'fixed_window': self.fixed_window_limit,
        }
    
    def token_bucket_limit(self, key, capacity, refill_rate, tokens_requested=1):
        """Token bucket algorithm for smooth rate limiting"""
        cache_key = f"bucket:{key}"
        now = time.time()
        
        bucket = cache.get(cache_key, {
            'tokens': capacity,
            'last_refill': now
        })
        
        # Refill tokens
        time_passed = now - bucket['last_refill']
        tokens_to_add = time_passed * refill_rate
        bucket['tokens'] = min(capacity, bucket['tokens'] + tokens_to_add)
        bucket['last_refill'] = now
        
        # Check if request can be served
        if bucket['tokens'] >= tokens_requested:
            bucket['tokens'] -= tokens_requested
            cache.set(cache_key, bucket, 3600)
            return True
        
        cache.set(cache_key, bucket, 3600)
        return False
    
    def sliding_window_limit(self, key, limit, window_size):
        """Sliding window rate limiting"""
        now = time.time()
        cache_key = f"sliding:{key}"
        
        # Get existing timestamps
        timestamps = cache.get(cache_key, [])
        
        # Remove old timestamps
        cutoff = now - window_size
        timestamps = [ts for ts in timestamps if ts > cutoff]
        
        # Check limit
        if len(timestamps) >= limit:
            return False
        
        # Add current timestamp
        timestamps.append(now)
        cache.set(cache_key, timestamps, window_size + 60)
        return True
    
    def fixed_window_limit(self, key, limit, window_size):
        """Fixed window rate limiting"""
        now = time.time()
        window = int(now // window_size)
        cache_key = f"fixed:{key}:{window}"
        
        current_count = cache.get(cache_key, 0)
        if current_count >= limit:
            return False
        
        cache.set(cache_key, current_count + 1, window_size)
        return True

class SecurityHeaderValidator:
    """Validate and enforce security headers"""
    
    REQUIRED_HEADERS = {
        'Content-Type': r'^application/json(;.*)?$',
        'User-Agent': r'.+',
        'Accept': r'.*application/json.*',
    }
    
    FORBIDDEN_HEADERS = [
        'X-Forwarded-Server',
        'X-Real-IP-Internal',
        'X-Debug',
    ]
    
    def validate_headers(self, request):
        """Validate request headers"""
        errors = []
        
        # Check required headers
        for header, pattern in self.REQUIRED_HEADERS.items():
            value = request.META.get(f'HTTP_{header.upper().replace("-", "_")}')
            if not value:
                errors.append(f"Missing required header: {header}")
            elif not re.match(pattern, value):
                errors.append(f"Invalid {header} header format")
        
        # Check forbidden headers
        for header in self.FORBIDDEN_HEADERS:
            if request.META.get(f'HTTP_{header.upper().replace("-", "_")}'):
                errors.append(f"Forbidden header present: {header}")
        
        # Check for potential header injection
        for key, value in request.META.items():
            if key.startswith('HTTP_') and ('\n' in str(value) or '\r' in str(value)):
                errors.append("Header injection attempt detected")
        
        return errors

class APISecurityMiddleware:
    """Comprehensive API security middleware"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.validator = APISecurityValidator()
        self.rate_limiter = APIRateLimiter()
        self.header_validator = SecurityHeaderValidator()
        
        # Whitelist for internal API calls
        self.internal_ips = getattr(settings, 'INTERNAL_IPS', ['127.0.0.1'])
        
        # Endpoints that require extra security
        self.critical_endpoints = [
            '/api/submit/',
            '/api/auth/login/',
            '/api/admin/',
        ]
    
    def __call__(self, request):
        # Skip middleware for non-API requests
        if not request.path.startswith('/api/'):
            return self.get_response(request)
        
        client_ip = self.validator.get_client_ip(request)
        
        # Basic security checks
        security_check = self.perform_security_checks(request, client_ip)
        if security_check:
            return security_check
        
        # Rate limiting
        rate_limit_check = self.check_rate_limits(request, client_ip)
        if rate_limit_check:
            return rate_limit_check
        
        # Process request
        response = self.get_response(request)
        
        # Add security headers to response
        self.add_security_headers(response)
        
        return response
    
    def perform_security_checks(self, request, client_ip):
        """Perform comprehensive security checks"""
        
        # Payload size validation
        if not self.validator.validate_payload_size(request):
            self.log_security_event(request, 'PAYLOAD_TOO_LARGE', 'HIGH')
            return JsonResponse(
                {'error': 'Payload too large'}, 
                status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
            )
        
        # Header validation
        header_errors = self.header_validator.validate_headers(request)
        if header_errors:
            self.log_security_event(request, 'INVALID_HEADERS', 'MEDIUM', 
                                   metadata={'errors': header_errors})
            return JsonResponse(
                {'error': 'Invalid request headers'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # API abuse detection
        is_abuse, abuse_reason = self.validator.detect_api_abuse(request, request.path)
        if is_abuse:
            self.log_security_event(request, 'API_ABUSE', 'HIGH',
                                   metadata={'reason': abuse_reason})
            return JsonResponse(
                {'error': 'API abuse detected'}, 
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        # Critical endpoint protection
        if request.path in self.critical_endpoints:
            critical_check = self.check_critical_endpoint(request, client_ip)
            if critical_check:
                return critical_check
        
        return None
    
    def check_critical_endpoint(self, request, client_ip):
        """Additional checks for critical endpoints"""
        
        # Timestamp validation for critical endpoints
        timestamp = request.headers.get('X-Timestamp')
        if timestamp and not self.validator.validate_timestamp(timestamp):
            self.log_security_event(request, 'INVALID_TIMESTAMP', 'HIGH')
            return JsonResponse(
                {'error': 'Invalid or expired timestamp'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Nonce validation
        nonce = request.headers.get('X-Nonce')
        if nonce and not self.validator.validate_nonce(nonce):
            self.log_security_event(request, 'REPLAY_ATTACK', 'CRITICAL')
            return JsonResponse(
                {'error': 'Invalid nonce - possible replay attack'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        return None
    
    def check_rate_limits(self, request, client_ip):
        """Apply rate limiting based on endpoint and user type"""
        
        # Different limits for different endpoints
        if request.path == '/api/submit/':
            # Form submissions: 5 per minute per IP
            if not self.rate_limiter.token_bucket_limit(
                f"submit:{client_ip}", capacity=5, refill_rate=1/12  # 5 per minute
            ):
                self.log_security_event(request, 'RATE_LIMIT_EXCEEDED', 'MEDIUM')
                return JsonResponse(
                    {'error': 'Form submission rate limit exceeded'}, 
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
        
        elif request.path.startswith('/api/auth/'):
            # Authentication: 3 per 5 minutes per IP
            if not self.rate_limiter.sliding_window_limit(
                f"auth:{client_ip}", limit=3, window_size=300
            ):
                self.log_security_event(request, 'AUTH_RATE_LIMIT', 'HIGH')
                return JsonResponse(
                    {'error': 'Authentication rate limit exceeded'}, 
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
        
        elif request.path.startswith('/api/admin/'):
            # Admin endpoints: 100 per hour per IP
            if not self.rate_limiter.fixed_window_limit(
                f"admin:{client_ip}", limit=100, window_size=3600
            ):
                self.log_security_event(request, 'ADMIN_RATE_LIMIT', 'HIGH')
                return JsonResponse(
                    {'error': 'Admin API rate limit exceeded'}, 
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
        
        else:
            # General API: 200 per hour per IP
            if not self.rate_limiter.token_bucket_limit(
                f"general:{client_ip}", capacity=200, refill_rate=200/3600
            ):
                return JsonResponse(
                    {'error': 'API rate limit exceeded'}, 
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
        
        return None
    
    def add_security_headers(self, response):
        """Add security headers to API responses"""
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Remove sensitive headers
        if 'Server' in response:
            del response['Server']
        if 'X-Powered-By' in response:
            del response['X-Powered-By']
    
    def log_security_event(self, request, event_type, severity, metadata=None):
        """Log security events"""
        try:
            SecurityEvent.objects.create(
                event_type=event_type,
                severity=severity,
                ip_address=self.validator.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                user=request.user if request.user.is_authenticated else None,
                description=f'API security event: {event_type}',
                metadata=metadata or {}
            )
        except Exception as e:
            # Log to file if database fails
            import logging
            logger = logging.getLogger('security_monitoring')
            logger.error(f"Failed to log security event: {e}")
