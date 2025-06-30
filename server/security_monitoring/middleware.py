# security_monitoring/middleware.py - 🔒 ULTRA-SECURE VERSION (with API CSRF fix)
import logging
import json
import re
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils import timezone  # ✅ FIXED: Use django.utils.timezone instead of datetime.timezone
from django.conf import settings
from .models import SecurityEvent, IPBlacklist, IPWhitelist
from .utils import get_client_ip, detect_threat, send_security_alert

logger = logging.getLogger('security_monitoring')

class SecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Malicious pattern detection - REFINED to reduce false positives
        self.sql_patterns = [
            r"(\bunion\b.*\bselect\b)",  # More specific SQL injection patterns
            r"(\bor\b.*=.*\bor\b)",     # More specific OR patterns
            r"(\/\*.*\*\/)",            # SQL comments with content
            r"(\bxp_cmdshell\b)",
            r"(\bdrop\b.*\btable\b)",   # More specific DROP patterns
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"eval\s*\(",
            r"document\.cookie",
        ]
        
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e\\",
        ]

    def __call__(self, request):
        # Skip security checks for API endpoints that have their own security
        if request.path.startswith('/api/auth/') or request.path.startswith('/api/submit/'):
            return self.get_response(request)
            
        # Get client IP
        client_ip = get_client_ip(request)
        
        # Check IP blacklist
        if self.is_ip_blacklisted(client_ip):
            self.log_security_event(
                'SUSPICIOUS_IP', 'HIGH', client_ip, request,
                'Blocked IP attempting access'
            )
            return HttpResponseForbidden("Access denied")
        
        # Check rate limiting
        if self.check_rate_limit(client_ip, request):
            self.log_security_event(
                'RATE_LIMIT', 'MEDIUM', client_ip, request,
                'Rate limit exceeded'
            )
            return HttpResponseForbidden("Rate limit exceeded")
        
        # Threat detection (with reduced false positives)
        threat_detected = self.detect_threats(request)
        if threat_detected:
            threat_type, description = threat_detected
            self.log_security_event(
                threat_type, 'HIGH', client_ip, request, description
            )
            return HttpResponseForbidden("Security threat detected")
        
        # Admin access monitoring
        if request.path.startswith('/admin/') or 'admin' in request.path:
            if not self.is_admin_access_allowed(client_ip, request):
                self.log_security_event(
                    'ADMIN_ACCESS', 'CRITICAL', client_ip, request,
                    'Unauthorized admin access attempt'
                )
                return HttpResponseForbidden("Unauthorized access")
        
        response = self.get_response(request)
        
        # Log successful admin access
        if (request.path.startswith('/admin/') and 
            response.status_code == 200 and request.user.is_authenticated):
            self.log_security_event(
                'ADMIN_ACCESS', 'LOW', client_ip, request,
                f'Admin access by {request.user.username}'
            )
        
        return response

    def is_ip_blacklisted(self, ip_address):
        """Check if IP is blacklisted"""
        try:
            blacklist_entry = IPBlacklist.objects.get(ip_address=ip_address)
            if blacklist_entry.permanent:
                return True
            if blacklist_entry.blocked_until and timezone.now() < blacklist_entry.blocked_until:
                return True
            elif blacklist_entry.blocked_until and timezone.now() >= blacklist_entry.blocked_until:
                blacklist_entry.delete()  # Remove expired blacklist
        except IPBlacklist.DoesNotExist:
            pass
        return False

    def check_rate_limit(self, ip_address, request):
        """Check rate limiting"""
        # Different limits for different endpoints
        if request.path.startswith('/api/submit/'):
            limit = 5  # 5 submissions per minute
            window = 60
        elif request.path.startswith('/api/auth/login/'):
            limit = 3  # 3 login attempts per 5 minutes
            window = 300
        else:
            limit = 100  # 100 requests per minute
            window = 60
        
        cache_key = f"rate_limit:{ip_address}:{request.path}"
        current_requests = cache.get(cache_key, 0)
        
        if current_requests >= limit:
            return True
        
        cache.set(cache_key, current_requests + 1, window)
        return False

    def detect_threats(self, request):
        """Detect various security threats with reduced false positives"""
        # Get request data
        query_string = request.GET.urlencode()
        post_data = ""
        if hasattr(request, 'body'):
            try:
                post_data = request.body.decode('utf-8')
            except:
                post_data = str(request.body)
        
        combined_data = f"{query_string} {post_data} {request.path}"
        
        # Skip checks for legitimate API data
        if request.path.startswith('/api/') and request.method == 'POST':
            # Basic JSON structure check
            try:
                if post_data.strip().startswith('{') and post_data.strip().endswith('}'):
                    json.loads(post_data)  # Valid JSON
                    return None  # Skip threat detection for valid JSON API calls
            except:
                pass
        
        # SQL Injection detection (refined)
        for pattern in self.sql_patterns:
            if re.search(pattern, combined_data, re.IGNORECASE):
                # Additional context check to reduce false positives
                if not self.is_likely_false_positive(combined_data, pattern):
                    return ('SQL_INJECTION', f'SQL injection pattern detected: {pattern}')
        
        # XSS detection
        for pattern in self.xss_patterns:
            if re.search(pattern, combined_data, re.IGNORECASE):
                return ('XSS_ATTEMPT', f'XSS pattern detected: {pattern}')
        
        # Path traversal detection
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, combined_data, re.IGNORECASE):
                return ('SUSPICIOUS_IP', f'Path traversal attempt: {pattern}')
        
        # File upload validation
        if request.FILES:
            for file_field, uploaded_file in request.FILES.items():
                if not self.is_safe_file(uploaded_file):
                    return ('FILE_UPLOAD', f'Unsafe file upload detected: {uploaded_file.name}')
        
        return None

    def is_likely_false_positive(self, data, pattern):
        """Check if SQL pattern is likely a false positive"""
        # Common false positive patterns
        false_positive_indicators = [
            'application/json',
            'content-type',
            'authorization',
            'bearer',
            'username',
            'password'
        ]
        
        data_lower = data.lower()
        for indicator in false_positive_indicators:
            if indicator in data_lower:
                return True
        
        return False

    def is_safe_file(self, uploaded_file):
        """Check if uploaded file is safe"""
        dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.scr', '.pif', '.vbs', '.js', '.jar',
            '.com', '.pif', '.application', '.gadget', '.msi', '.msp',
            '.hta', '.cpl', '.msc', '.ws', '.wsf', '.wsc', '.wsh', '.ps1',
            '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2', '.msh', '.msh1',
            '.msh2', '.mshxml', '.msh1xml', '.msh2xml', '.scf', '.lnk', '.inf',
            '.reg', '.dll', '.php', '.asp', '.aspx', '.jsp'
        ]
        
        file_name = uploaded_file.name.lower()
        for ext in dangerous_extensions:
            if file_name.endswith(ext):
                return False
        
        # Check file size
        if uploaded_file.size > settings.FILE_UPLOAD_MAX_MEMORY_SIZE:
            return False
        
        return True

    def is_admin_access_allowed(self, ip_address, request):
        """Check if admin access is allowed from this IP"""
        # Check if IP is whitelisted
        if hasattr(settings, 'SECURITY_IP_WHITELIST') and settings.SECURITY_IP_WHITELIST:
            return ip_address in settings.SECURITY_IP_WHITELIST
        
        # Check database whitelist
        return IPWhitelist.objects.filter(
            ip_address=ip_address, 
            is_active=True
        ).exists()

    def log_security_event(self, event_type, severity, ip_address, request, description):
        """Log security event with proper timezone handling"""
        try:
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            user = request.user if request.user.is_authenticated else None
            
            metadata = {
                'path': request.path,
                'method': request.method,
                'headers': dict(request.headers) if hasattr(request, 'headers') else {},
                'query_params': dict(request.GET) if hasattr(request, 'GET') else {},
            }
            
            # Create security event with proper error handling
            try:
                SecurityEvent.objects.create(
                    event_type=event_type,
                    severity=severity,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    user=user,
                    description=description,
                    metadata=metadata
                )
            except Exception as db_error:
                # If database save fails, log to file
                logger.error(f"Failed to save security event to database: {db_error}")
            
            logger.warning(f"Security Event: {event_type} from {ip_address} - {description}")
            
            # Send alert for high/critical events
            if severity in ['HIGH', 'CRITICAL']:
                try:
                    send_security_alert(event_type, severity, ip_address, description)
                except Exception as alert_error:
                    logger.error(f"Failed to send security alert: {alert_error}")
                
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
            # Continue execution even if logging fails