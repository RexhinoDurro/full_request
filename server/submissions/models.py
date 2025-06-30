# submissions/models.py - FULL SECURITY VERSION with auditlog restored
from django.db import models
from django.utils import timezone
from django_cryptography.fields import encrypt
from auditlog.registry import auditlog  # ✅ RESTORED: Full audit logging
import hashlib
import uuid

class Submission(models.Model):
    """🔒 ULTRA-SECURE: Advanced submission model with field-level encryption and comprehensive security features"""
    
    # 🔒 SECURITY: Unique identifier that's not sequential (prevents enumeration attacks)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    
    # 🔒 ENCRYPTION: All PII fields are encrypted at the database level
    step1 = encrypt(models.TextField(blank=True, null=True, help_text="Company name"))
    step2 = encrypt(models.CharField(max_length=100, blank=True, null=True, help_text="Service type"))
    step3 = encrypt(models.CharField(max_length=100, blank=True, null=True, help_text="When issue occurred"))
    step4 = encrypt(models.CharField(max_length=100, blank=True, null=True, help_text="Company acknowledgment"))
    step5 = encrypt(models.CharField(max_length=100, blank=True, null=True, help_text="Primary goal"))
    step6 = encrypt(models.CharField(max_length=100, blank=True, null=True, help_text="How heard about us"))
    step7 = encrypt(models.CharField(max_length=100, blank=True, null=True, help_text="Preferred communication"))
    step8 = encrypt(models.TextField(blank=True, null=True, help_text="Case summary"))
    
    # 🔒 ENCRYPTION: Contact information (PII) - fully encrypted
    name = encrypt(models.CharField(max_length=200))
    email = encrypt(models.EmailField())
    phone = encrypt(models.CharField(max_length=20))
    
    # 🔒 SECURITY: Queryable fields (hashed for privacy, indexed for performance)
    country = models.CharField(max_length=10, default='US')  # Country codes are not PII
    email_hash = models.CharField(max_length=64, db_index=True, default='')  # For duplicate detection
    phone_hash = models.CharField(max_length=64, db_index=True, default='')  # For duplicate detection
    
    # 🔒 SECURITY: Metadata for forensics and compliance
    submitted_at = models.DateTimeField(auto_now_add=True, db_index=True)
    ip_address_hash = models.CharField(max_length=64, db_index=True, default='')  # Hashed for privacy
    user_agent_hash = models.CharField(max_length=64, null=True, blank=True, default='')  # Hashed for privacy
    
    # 🔒 COMPLIANCE: Data classification and retention
    data_classification = models.CharField(
        max_length=20, 
        choices=[
            ('PUBLIC', 'Public'),
            ('INTERNAL', 'Internal'),
            ('CONFIDENTIAL', 'Confidential'),
            ('RESTRICTED', 'Restricted'),
        ],
        default='CONFIDENTIAL'
    )
    retention_date = models.DateTimeField(null=True, blank=True)  # For GDPR/CCPA compliance
    anonymized = models.BooleanField(default=False)  # For right to be forgotten
    
    # 🔒 INTEGRITY: Data integrity verification
    checksum = models.CharField(max_length=64, editable=False, default='')  # Tamper detection
    
    class Meta:
        ordering = ['-submitted_at']
        verbose_name = 'Encrypted Form Submission'
        verbose_name_plural = 'Encrypted Form Submissions'
        indexes = [
            models.Index(fields=['submitted_at', 'country']),
            models.Index(fields=['email_hash']),
            models.Index(fields=['anonymized', 'retention_date']),
        ]
    
    def save(self, *args, **kwargs):
        # 🔒 SECURITY: Generate hashes for indexing and duplicate detection
        if self.email:
            self.email_hash = hashlib.sha256(self.email.lower().encode()).hexdigest()
        if self.phone:
            self.phone_hash = hashlib.sha256(self.phone.encode()).hexdigest()
        
        # 🔒 COMPLIANCE: Set retention date (e.g., 7 years for legal compliance)
        if not self.retention_date:
            self.retention_date = timezone.now() + timezone.timedelta(days=2555)  # 7 years
        
        # 🔒 INTEGRITY: Generate integrity checksum for tamper detection
        data_to_hash = f"{self.step1}{self.step2}{self.step3}{self.step4}{self.step5}{self.step6}{self.step7}{self.step8}{self.name}{self.email}{self.phone}"
        self.checksum = hashlib.sha256(data_to_hash.encode()).hexdigest()
        
        super().save(*args, **kwargs)
    
    def verify_integrity(self):
        """🔒 SECURITY: Verify data integrity using checksum"""
        current_data = f"{self.step1}{self.step2}{self.step3}{self.step4}{self.step5}{self.step6}{self.step7}{self.step8}{self.name}{self.email}{self.phone}"
        current_checksum = hashlib.sha256(current_data.encode()).hexdigest()
        return current_checksum == self.checksum
    
    def anonymize(self):
        """🔒 COMPLIANCE: Anonymize PII while keeping data for analytics (GDPR compliance)"""
        self.name = "ANONYMIZED"
        self.email = f"anonymized_{self.uuid}@example.com"
        self.phone = "ANONYMIZED"
        self.anonymized = True
        self.save()
    
    @property
    def short_summary(self):
        """Return a short summary (only if not anonymized)"""
        if self.anonymized:
            return "Anonymized submission"
        if self.step8:
            return self.step8[:100] + "..." if len(self.step8) > 100 else self.step8
        return "No summary provided"
    
    def __str__(self):
        if self.anonymized:
            return f"Anonymized Submission {self.uuid} ({self.submitted_at.strftime('%Y-%m-%d')})"
        return f"{self.name} - {self.country} ({self.submitted_at.strftime('%Y-%m-%d %H:%M')})"

# ✅ RESTORED: Register for comprehensive audit logging
auditlog.register(Submission)

class DataRetentionLog(models.Model):
    """🔒 COMPLIANCE: Log all data retention and deletion activities for audit trails"""
    action_type = models.CharField(max_length=20, choices=[
        ('ANONYMIZE', 'Anonymize'),
        ('DELETE', 'Delete'),
        ('EXPORT', 'Export'),
        ('RESTORE', 'Restore'),
    ])
    submission_uuid = models.UUIDField()
    performed_by = models.ForeignKey('auth.User', on_delete=models.PROTECT)
    performed_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField()
    metadata = models.JSONField(default=dict)
    
    class Meta:
        ordering = ['-performed_at']

class SecurityIncident(models.Model):
    """🔒 SECURITY: Track and manage security incidents"""
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('INVESTIGATING', 'Investigating'),
        ('RESOLVED', 'Resolved'),
        ('CLOSED', 'Closed'),
    ]
    
    incident_type = models.CharField(max_length=50)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='OPEN')
    description = models.TextField()
    affected_submissions = models.ManyToManyField(Submission, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    assigned_to = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        ordering = ['-discovered_at']

# ✅ RESTORED: Register all models for audit logging
auditlog.register(DataRetentionLog)
auditlog.register(SecurityIncident)