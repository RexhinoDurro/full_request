# authentication/admin_security.py - Enhanced admin security
from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.admin import AdminSite
from django.http import HttpRequest
from security_monitoring.utils import log_security_event, get_client_ip
import logging

logger = logging.getLogger('security_monitoring')

class SecureAdminSite(AdminSite):
    """Ultra-secure admin site with anonymity features"""
    
    site_header = "Secure Form Management"
    site_title = "Secure Admin"
    index_title = "Form Management Dashboard"
    
    def has_permission(self, request):
        """Enhanced permission checking with logging"""
        has_perm = super().has_permission(request)
        
        if has_perm:
            # Log successful admin access
            log_security_event(
                event_type='ADMIN_ACCESS',
                severity='MEDIUM',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                user=request.user,
                description=f'Admin panel access by {request.user.username}'
            )
        else:
            # Log unauthorized access attempt
            log_security_event(
                event_type='ADMIN_ACCESS',
                severity='HIGH',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                user=request.user if request.user.is_authenticated else None,
                description='Unauthorized admin panel access attempt'
            )
        
        return has_perm
    
    def login(self, request, extra_context=None):
        """Enhanced login with security logging"""
        if request.method == 'POST':
            username = request.POST.get('username', '')
            
            # Log login attempt
            log_security_event(
                event_type='LOGIN_ATTEMPT',
                severity='LOW',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f'Admin login attempt for username: {username[:10]}...'  # Partial username for privacy
            )
        
        return super().login(request, extra_context)
    
    def logout(self, request, extra_context=None):
        """Enhanced logout with security logging"""
        if request.user.is_authenticated:
            log_security_event(
                event_type='ADMIN_ACCESS',
                severity='LOW',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                user=request.user,
                description=f'Admin logout by {request.user.username}'
            )
        
        return super().logout(request, extra_context)

# Create custom admin site instance
admin_site = SecureAdminSite(name='secure_admin')

# Register models with enhanced security
from submissions.models import Submission, DataRetentionLog, SecurityIncident
from security_monitoring.models import SecurityEvent, IPWhitelist, IPBlacklist

class SecureSubmissionAdmin(admin.ModelAdmin):
    """Secure admin interface for submissions"""
    list_display = ['id', 'uuid', 'country', 'submitted_at', 'anonymized']
    list_filter = ['country', 'submitted_at', 'anonymized', 'data_classification']
    search_fields = ['uuid', 'country']
    readonly_fields = ['uuid', 'submitted_at', 'checksum', 'email_hash', 'phone_hash']
    
    def get_queryset(self, request):
        """Log data access"""
        qs = super().get_queryset(request)
        
        log_security_event(
            event_type='DATA_ACCESS',
            severity='MEDIUM',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            user=request.user,
            description=f'Admin accessed submissions list ({qs.count()} records)',
            metadata={'record_count': qs.count()}
        )
        
        return qs
    
    def view_on_site(self, obj):
        return None  # Disable view on site for security

class SecurityEventAdmin(admin.ModelAdmin):
    """Admin interface for security events"""
    list_display = ['event_type', 'severity', 'ip_address', 'timestamp', 'resolved']
    list_filter = ['event_type', 'severity', 'resolved', 'timestamp']
    search_fields = ['ip_address', 'description']
    readonly_fields = ['timestamp']
    
    def has_delete_permission(self, request, obj=None):
        # Prevent deletion of security logs
        return False

# Register with secure admin site
admin_site.register(Submission, SecureSubmissionAdmin)
admin_site.register(SecurityEvent, SecurityEventAdmin)
admin_site.register(DataRetentionLog)
admin_site.register(SecurityIncident)
admin_site.register(IPWhitelist)
admin_site.register(IPBlacklist)

# Override default admin site
admin.site = admin_site