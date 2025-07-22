# security_monitoring/subdomain_middleware.py - Admin subdomain security
import logging
from django.conf import settings
from django.http import HttpResponseForbidden, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from security_monitoring.utils import get_client_ip, log_security_event

logger = logging.getLogger('admin_subdomain')

class AdminSubdomainSecurityMiddleware(MiddlewareMixin):
    """🔒 SECURITY: Enhanced security middleware for admin subdomain"""
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        
        # Load admin subdomain configuration
        self.admin_subdomains = getattr(settings, 'ADMIN_SUBDOMAIN_DOMAINS', [
            'admin-secure.cryptofacilities.eu',
            'admin.cryptofacilities.eu',
        ])
        
        self.admin_ip_whitelist = getattr(settings, 'ADMIN_IP_WHITELIST', [])
        self.secure_subdomain_admin = getattr(settings, 'SECURE_SUBDOMAIN_ADMIN', True)
        
        logger.info(f"Admin subdomain security initialized: {self.admin_subdomains}")
    
    def process_request(self, request):
        """Process incoming requests for admin subdomain security"""
        
        # Get request details
        host = request.get_host().lower()
        client_ip = get_client_ip(request)
        
        # Check if this is an admin subdomain request
        is_admin_subdomain = any(domain in host for domain in self.admin_subdomains)
        
        if is_admin_subdomain:
            # 🔒 SECURITY: Enhanced logging for admin subdomain access
            logger.info(f"Admin subdomain access: {host} from {client_ip}")
            
            # Apply additional security checks for admin subdomain
            security_check = self.perform_admin_subdomain_checks(request, host, client_ip)
            if security_check:
                return security_check
            
            # Add custom headers for admin subdomain identification
            request.META['HTTP_X_ADMIN_SUBDOMAIN'] = 'true'
            request.META['HTTP_X_ADMIN_DOMAIN'] = host
        
        return None
    
    def process_response(self, request, response):
        """Process responses for admin subdomain"""
        
        # Check if this was an admin subdomain request
        if request.META.get('HTTP_X_ADMIN_SUBDOMAIN') == 'true':
            # Add security headers specific to admin subdomain
            response = self.add_admin_security_headers(response, request)
            
            # Log successful admin subdomain response
            admin_domain = request.META.get('HTTP_X_ADMIN_DOMAIN', 'unknown')
            client_ip = get_client_ip(request)
            
            logger.info(f"Admin subdomain response: {response.status_code} for {admin_domain} from {client_ip}")
        
        return response
    
    def perform_admin_subdomain_checks(self, request, host, client_ip):
        """Perform enhanced security checks for admin subdomain"""
        
        if not self.secure_subdomain_admin:
            return None  # Skip checks in development
        
        # 🔒 SECURITY: IP whitelist check (if configured)
        if self.admin_ip_whitelist and client_ip not in self.admin_ip_whitelist:
            log_security_event(
                'ADMIN_IP_BLOCKED', 'HIGH', 
                client_ip, request.META.get('HTTP_USER_AGENT', ''),
                request.user if request.user.is_authenticated else None,
                f'Admin subdomain access from non-whitelisted IP: {client_ip}',
                {
                    'admin_domain': host,
                    'blocked_ip': client_ip,
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200],
                    'path': request.path
                }
            )
            
            return JsonResponse({
                'error': 'Access denied',
                'message': 'Your IP address is not authorized to access the admin panel'
            }, status=403)
        
        # 🔒 SECURITY: Check for suspicious patterns in admin subdomain requests
        suspicious_patterns = [
            'wp-admin', 'phpmyadmin', 'admin.php', 'login.php',
            'xmlrpc.php', 'config.php', 'setup.php', 'install.php'
        ]
        
        path = request.path.lower()
        for pattern in suspicious_patterns:
            if pattern in path:
                log_security_event(
                    'ADMIN_SUBDOMAIN_ATTACK', 'HIGH',
                    client_ip, request.META.get('HTTP_USER_AGENT', ''),
                    None,
                    f'Suspicious pattern in admin subdomain path: {pattern}',
                    {
                        'admin_domain': host,
                        'suspicious_pattern': pattern,
                        'request_path': path,
                        'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200]
                    }
                )
                
                return HttpResponseForbidden("Access denied")
        
        # 🔒 SECURITY: Rate limiting for admin subdomain (stricter than main site)
        if self.is_admin_rate_limited(client_ip, request.path):
            log_security_event(
                'ADMIN_RATE_LIMIT', 'HIGH',
                client_ip, request.META.get('HTTP_USER_AGENT', ''),
                request.user if request.user.is_authenticated else None,
                'Admin subdomain rate limit exceeded',
                {
                    'admin_domain': host,
                    'request_path': request.path
                }
            )
            
            return JsonResponse({
                'error': 'Rate limit exceeded',
                'message': 'Too many requests to admin subdomain'
            }, status=429)
        
        # 🔒 SECURITY: Check for valid User-Agent (basic bot detection)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        if not user_agent or len(user_agent) < 10:
            log_security_event(
                'ADMIN_SUSPICIOUS_UA', 'MEDIUM',
                client_ip, user_agent,
                None,
                'Admin subdomain access with suspicious User-Agent',
                {
                    'admin_domain': host,
                    'user_agent': user_agent,
                    'request_path': request.path
                }
            )
            
            # Don't block, but log for monitoring
        
        return None
    
    def add_admin_security_headers(self, response, request):
        """Add enhanced security headers for admin subdomain"""
        
        # 🔒 SECURITY: Strict security headers for admin
        response['X-Admin-Subdomain'] = 'protected'
        response['X-Frame-Options'] = 'DENY'
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # 🔒 SECURITY: Enhanced CSP for admin subdomain
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https:; "
            "connect-src 'self' https://cryptofacilities.eu; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        response['Content-Security-Policy'] = csp_policy
        
        # 🔒 SECURITY: Cache control for admin resources
        if request.path.endswith(('.html', '.htm')):
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
        
        # 🔒 SECURITY: Remove server identification
        if 'Server' in response:
            del response['Server']
        if 'X-Powered-By' in response:
            del response['X-Powered-By']
        
        return response
    
    def is_admin_rate_limited(self, ip_address, path):
        """Check rate limiting for admin subdomain (stricter limits)"""
        from django.core.cache import cache
        from django.utils import timezone
        
        # Different limits for different admin endpoints
        if '/api/auth/' in path:
            limit = 3  # 3 auth attempts per 10 minutes
            window = 600
        elif '/api/admin/' in path:
            limit = 60  # 60 admin API calls per 10 minutes
            window = 600
        else:
            limit = 120  # 120 general requests per 10 minutes
            window = 600
        
        cache_key = f"admin_rate_limit:{ip_address}:{path.split('/')[1] if '/' in path else 'root'}"
        
        try:
            current_requests = cache.get(cache_key, 0)
            
            if current_requests >= limit:
                return True
            
            cache.set(cache_key, current_requests + 1, window)
            return False
            
        except Exception as e:
            logger.error(f"Admin rate limiting error: {e}")
            return False
    
    def log_admin_access(self, request, client_ip, host):
        """Log admin subdomain access for security monitoring"""
        
        try:
            log_security_event(
                'ADMIN_SUBDOMAIN_ACCESS', 'LOW',
                client_ip, request.META.get('HTTP_USER_AGENT', ''),
                request.user if request.user.is_authenticated else None,
                f'Admin subdomain accessed: {host}',
                {
                    'admin_domain': host,
                    'request_path': request.path,
                    'request_method': request.method,
                    'referrer': request.META.get('HTTP_REFERER', ''),
                    'user_authenticated': request.user.is_authenticated if hasattr(request, 'user') else False
                }
            )
        except Exception as e:
            logger.error(f"Failed to log admin subdomain access: {e}")


class AdminOriginValidationMiddleware(MiddlewareMixin):
    """🔒 SECURITY: Validate Origin header for admin API requests"""
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        self.allowed_admin_origins = [
            'https://admin-secure.cryptofacilities.eu',
            'https://admin.cryptofacilities.eu',
        ]
        
        if settings.DEBUG:
            self.allowed_admin_origins.extend([
                'http://localhost:3000',
                'http://127.0.0.1:3000',
                'http://localhost:5173',
                'http://127.0.0.1:5173',
            ])
    
    def process_request(self, request):
        """Validate Origin header for admin API requests"""
        
        # Only check admin API endpoints
        if not request.path.startswith('/api/admin/') and not request.path.startswith('/api/auth/'):
            return None
        
        # Skip GET requests and OPTIONS (preflight)
        if request.method in ['GET', 'OPTIONS']:
            return None
        
        origin = request.META.get('HTTP_ORIGIN')
        
        if not origin:
            # No origin header - could be direct API call
            log_security_event(
                'ADMIN_API_NO_ORIGIN', 'MEDIUM',
                get_client_ip(request), request.META.get('HTTP_USER_AGENT', ''),
                request.user if request.user.is_authenticated else None,
                'Admin API request without Origin header',
                {
                    'request_path': request.path,
                    'request_method': request.method,
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200]
                }
            )
            
            # Allow for now, but log for monitoring
            return None
        
        if origin not in self.allowed_admin_origins:
            log_security_event(
                'ADMIN_API_INVALID_ORIGIN', 'HIGH',
                get_client_ip(request), request.META.get('HTTP_USER_AGENT', ''),
                None,
                f'Admin API request from invalid origin: {origin}',
                {
                    'invalid_origin': origin,
                    'request_path': request.path,
                    'allowed_origins': self.allowed_admin_origins
                }
            )
            
            return JsonResponse({
                'error': 'Invalid origin',
                'message': 'Request origin not allowed for admin API'
            }, status=403)
        
        return None