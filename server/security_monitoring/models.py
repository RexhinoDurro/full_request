# security_monitoring/models.py - 🔒 ULTRA-SECURE VERSION
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from auditlog.registry import auditlog
import json

class SecurityEvent(models.Model):
    """🔒 SECURITY: Comprehensive security event tracking and monitoring"""
    EVENT_TYPES = [
        ('LOGIN_ATTEMPT', 'Login Attempt'),
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAILURE', 'Login Failure'),
        ('RATE_LIMIT', 'Rate Limit Exceeded'),
        ('SUSPICIOUS_IP', 'Suspicious IP Activity'),
        ('SQL_INJECTION', 'SQL Injection Attempt'),
        ('XSS_ATTEMPT', 'XSS Attempt'),
        ('CSRF_FAILURE', 'CSRF Failure'),
        ('FILE_UPLOAD', 'File Upload'),
        ('DATA_EXPORT', 'Data Export'),
        ('ADMIN_ACCESS', 'Admin Access'),
        ('API_ABUSE', 'API Abuse'),
        ('FORM_SPAM', 'Form Spam'),
        ('BRUTE_FORCE', 'Brute Force Attack'),
        ('DATA_BREACH_ATTEMPT', 'Data Breach Attempt'),
        ('PRIVILEGE_ESCALATION', 'Privilege Escalation'),
        ('SUSPICIOUS_ACTIVITY', 'Suspicious Activity'),
        ('REPLAY_ATTACK', 'Replay Attack'),
        ('DATA_DELETION', 'Data Deletion'),
        ('BULK_DATA_DELETION', 'Bulk Data Deletion'),
        ('SENSITIVE_DATA_ACCESS', 'Sensitive Data Access'),
        ('API_ERROR', 'API Error'),
        ('FORM_SUBMISSION', 'Form Submission'),
        ('FORM_VALIDATION_ERROR', 'Form Validation Error'),
        ('CSP_VIOLATION', 'CSP Violation'),
    ]
    
    SEVERITY_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='LOW')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    description = models.TextField()
    metadata = models.JSONField(default=dict)
    timestamp = models.DateTimeField(default=timezone.now)
    resolved = models.BooleanField(default=False)
    
    # 🔒 SECURITY: Additional tracking fields
    geolocation = models.CharField(max_length=100, blank=True, null=True)
    threat_score = models.IntegerField(default=0)  # 0-100 threat assessment
    automated_response = models.CharField(max_length=50, blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['severity', 'resolved']),
            models.Index(fields=['threat_score', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.event_type} - {self.ip_address} ({self.timestamp})"

class IPWhitelist(models.Model):
    """🔒 SECURITY: IP address whitelist for trusted sources"""
    ip_address = models.GenericIPAddressField(unique=True)
    description = models.CharField(max_length=200)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)  # Optional expiration
    
    def __str__(self):
        return f"{self.ip_address} - {self.description}"

class IPBlacklist(models.Model):
    """🔒 SECURITY: IP address blacklist for blocked sources"""
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=200)
    blocked_until = models.DateTimeField(null=True, blank=True)
    permanent = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    threat_level = models.CharField(max_length=10, choices=[
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ], default='MEDIUM')
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason}"

class ThreatIntelligence(models.Model):
    """🔒 SECURITY: External threat intelligence data"""
    THREAT_TYPES = [
        ('IP', 'Malicious IP'),
        ('DOMAIN', 'Malicious Domain'),
        ('HASH', 'File Hash'),
        ('EMAIL', 'Malicious Email'),
        ('URL', 'Malicious URL'),
    ]
    
    threat_type = models.CharField(max_length=10, choices=THREAT_TYPES)
    indicator = models.CharField(max_length=255, db_index=True)
    description = models.TextField()
    confidence = models.IntegerField(default=50)  # 0-100 confidence level
    source = models.CharField(max_length=100)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['threat_type', 'indicator']
        indexes = [
            models.Index(fields=['threat_type', 'indicator']),
            models.Index(fields=['confidence', 'is_active']),
        ]

class SecurityAlert(models.Model):
    """🔒 SECURITY: High-priority security alerts requiring attention"""
    ALERT_TYPES = [
        ('CRITICAL_BREACH', 'Critical Security Breach'),
        ('DATA_EXFILTRATION', 'Data Exfiltration Attempt'),
        ('MASS_LOGIN_FAILURES', 'Mass Login Failures'),
        ('ADMIN_COMPROMISE', 'Admin Account Compromise'),
        ('SYSTEM_INTRUSION', 'System Intrusion'),
        ('MALWARE_DETECTED', 'Malware Detected'),
    ]
    
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('INVESTIGATING', 'Investigating'),
        ('CONTAINED', 'Contained'),
        ('RESOLVED', 'Resolved'),
        ('FALSE_POSITIVE', 'False Positive'),
    ]
    
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES)
    title = models.CharField(max_length=200)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SecurityEvent.SEVERITY_LEVELS)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='OPEN')
    
    # Relationships
    related_events = models.ManyToManyField(SecurityEvent, blank=True)
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Response tracking
    response_actions = models.JSONField(default=list)
    impact_assessment = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'severity']),
            models.Index(fields=['created_at', 'status']),
        ]

class SecurityMetrics(models.Model):
    """🔒 MONITORING: Daily security metrics and KPIs"""
    date = models.DateField(unique=True)
    
    # Event counts
    total_events = models.IntegerField(default=0)
    critical_events = models.IntegerField(default=0)
    high_events = models.IntegerField(default=0)
    medium_events = models.IntegerField(default=0)
    low_events = models.IntegerField(default=0)
    
    # Attack types
    sql_injection_attempts = models.IntegerField(default=0)
    xss_attempts = models.IntegerField(default=0)
    brute_force_attempts = models.IntegerField(default=0)
    rate_limit_violations = models.IntegerField(default=0)
    
    # Response metrics
    average_response_time = models.FloatField(default=0.0)  # Minutes
    false_positive_rate = models.FloatField(default=0.0)    # Percentage
    
    # System health
    uptime_percentage = models.FloatField(default=100.0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-date']

# ✅ SECURITY: Register all models for comprehensive audit logging
auditlog.register(SecurityEvent)
auditlog.register(IPWhitelist)
auditlog.register(IPBlacklist)
auditlog.register(ThreatIntelligence)
auditlog.register(SecurityAlert)
auditlog.register(SecurityMetrics)