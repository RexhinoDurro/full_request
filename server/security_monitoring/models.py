# security_monitoring/models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import json

class SecurityEvent(models.Model):
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
    ]
    
    SEVERITY_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='LOW')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    description = models.TextField()
    metadata = models.JSONField(default=dict)
    timestamp = models.DateTimeField(default=timezone.now)
    resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['severity', 'resolved']),
        ]
    
    def __str__(self):
        return f"{self.event_type} - {self.ip_address} ({self.timestamp})"

class IPWhitelist(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    description = models.CharField(max_length=200)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.ip_address} - {self.description}"

class IPBlacklist(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=200)
    blocked_until = models.DateTimeField(null=True, blank=True)
    permanent = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason}"