# security_monitoring/utils.py - FIXED VERSION
from django.utils import timezone  # ✅ FIXED: Use django.utils.timezone
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger('security_monitoring')

def get_client_ip(request):
    """Get the real client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')  # Default fallback
    return ip

def detect_threat(data):
    """Advanced threat detection using rule-based approach"""
    if not data:
        return False
        
    # Convert to string if not already
    data_str = str(data).lower()
    
    # Reduced suspicious keywords to avoid false positives
    suspicious_keywords = [
        'script>', 'alert(', 'onload=', 'onerror=', 'eval(', 'exec(',
        'union select', 'drop table', 'delete from', 'insert into',
        '../etc/passwd', 'cmd.exe', 'powershell.exe'
    ]
    
    for keyword in suspicious_keywords:
        if keyword in data_str:
            return True
    return False

def send_security_alert(event_type, severity, ip_address, description):
    """Send security alert email with error handling"""
    if not getattr(settings, 'SECURITY_EMAIL_NOTIFICATIONS', False):
        return
    
    try:
        subject = f"🚨 Security Alert - {severity} - {event_type}"
        message = f"""
Security Event Detected:

Event Type: {event_type}
Severity: {severity}
IP Address: {ip_address}
Description: {description}
Time: {timezone.now()}

Please investigate immediately.
        """
        
        # Use Django's send_mail with error handling
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            ['admin@formsite.com'],  # Configure this in production
            fail_silently=True,  # Don't break the app if email fails
        )
        logger.info(f"Security alert sent for {event_type}")
        
    except Exception as e:
        logger.error(f"Failed to send security alert: {e}")
        # Don't raise the exception - just log it

def log_security_event(event_type, severity, ip_address, user_agent='', user=None, description='', metadata=None):
    """Simplified security event logging"""
    try:
        # Import here to avoid circular imports
        from .models import SecurityEvent
        
        SecurityEvent.objects.create(
            event_type=event_type,
            severity=severity,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else '',  # Truncate long user agents
            user=user,
            description=description[:1000] if description else '',  # Truncate long descriptions
            metadata=metadata or {}
        )
        
        logger.warning(f"Security Event: {event_type} from {ip_address} - {description}")
        
    except Exception as e:
        # If database logging fails, at least log to file
        logger.error(f"Failed to log security event to database: {e}")
        logger.warning(f"Security Event (fallback): {event_type} from {ip_address} - {description}")

def validate_ip_address(ip_address):
    """Validate IP address format"""
    import ipaddress
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def is_safe_user_agent(user_agent):
    """Check if user agent seems legitimate"""
    if not user_agent:
        return False
    
    # Too short or too long user agents are suspicious
    if len(user_agent) < 10 or len(user_agent) > 1000:
        return False
    
    # Check for obvious attack patterns
    attack_patterns = ['<script', 'javascript:', 'eval(', 'alert(']
    user_agent_lower = user_agent.lower()
    
    for pattern in attack_patterns:
        if pattern in user_agent_lower:
            return False
    
    return True