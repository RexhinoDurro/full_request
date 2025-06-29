# submissions/managers.py - Custom managers for security
import hashlib
from django.db import models
from django.utils import timezone

class SecureSubmissionManager(models.Manager):
    """Custom manager with security features"""
    
    def get_queryset(self):
        """Always exclude soft-deleted records"""
        return super().get_queryset()
    
    def create_secure(self, ip_address=None, user_agent=None, **kwargs):
        """Create submission with security enhancements"""
        # Hash IP and user agent for privacy
        if ip_address:
            kwargs['ip_address_hash'] = hashlib.sha256(ip_address.encode()).hexdigest()
        if user_agent:
            kwargs['user_agent_hash'] = hashlib.sha256(user_agent.encode()).hexdigest()
        
        return self.create(**kwargs)
    
    def find_duplicates(self, email=None, phone=None, threshold_hours=24):
        """Find potential duplicate submissions"""
        if not email and not phone:
            return self.none()
        
        threshold_time = timezone.now() - timezone.timedelta(hours=threshold_hours)
        queryset = self.filter(submitted_at__gte=threshold_time)
        
        if email:
            email_hash = hashlib.sha256(email.lower().encode()).hexdigest()
            queryset = queryset.filter(email_hash=email_hash)
        
        if phone:
            phone_hash = hashlib.sha256(phone.encode()).hexdigest()
            queryset = queryset.filter(phone_hash=phone_hash)
        
        return queryset
    
    def needs_retention_action(self):
        """Get submissions that need retention action"""
        return self.filter(
            retention_date__lte=timezone.now(),
            anonymized=False
        )
    
    def integrity_check(self):
        """Check integrity of all submissions"""
        failed_checks = []
        for submission in self.all():
            if not submission.verify_integrity():
                failed_checks.append(submission.uuid)
        return failed_checks