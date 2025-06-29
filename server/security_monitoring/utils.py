# security_monitoring/utils.py
from datetime import timezone
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
        ip = request.META.get('REMOTE_ADDR')
    return ip

def detect_threat(data):
    """Advanced threat detection using ML or rule-based approach"""
    # This could be enhanced with machine learning models
    suspicious_keywords = [
        'script', 'alert', 'onload', 'onerror', 'eval', 'exec',
        'union', 'select', 'drop', 'delete', 'insert', 'update',
        '../', '..\\', 'etc/passwd', 'cmd.exe', 'powershell'
    ]
    
    for keyword in suspicious_keywords:
        if keyword.lower() in data.lower():
            return True
    return False

def send_security_alert(event_type, severity, ip_address, description):
    """Send security alert email"""
    if not getattr(settings, 'SECURITY_EMAIL_NOTIFICATIONS', False):
        return
    
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
    
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            ['admin@formsite.com'],  # Configure this
            fail_silently=False,
        )
    except Exception as e:
        logger.error(f"Failed to send security alert: {e}")
