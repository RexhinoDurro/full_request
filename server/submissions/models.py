from django.db import models

class Submission(models.Model):
    # Form step responses
    step1 = models.TextField(blank=True, null=True, help_text="Company name")
    step2 = models.CharField(max_length=100, blank=True, null=True, help_text="Service type")
    step3 = models.CharField(max_length=100, blank=True, null=True, help_text="When issue occurred")
    step4 = models.CharField(max_length=100, blank=True, null=True, help_text="Company acknowledgment")
    step5 = models.CharField(max_length=100, blank=True, null=True, help_text="Primary goal")
    step6 = models.CharField(max_length=100, blank=True, null=True, help_text="How heard about us")
    step7 = models.CharField(max_length=100, blank=True, null=True, help_text="Preferred communication")
    step8 = models.TextField(blank=True, null=True, help_text="Case summary")
    
    # Contact information
    name = models.CharField(max_length=200)
    email = models.EmailField()
    country = models.CharField(max_length=10, default='US')
    phone = models.CharField(max_length=20)
    
    # Metadata
    submitted_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        ordering = ['-submitted_at']
        verbose_name = 'Form Submission'
        verbose_name_plural = 'Form Submissions'
    
    def __str__(self):
        return f"{self.name} - {self.email} ({self.submitted_at.strftime('%Y-%m-%d %H:%M')})"
    
    @property
    def short_summary(self):
        """Return a short summary of the submission for admin view"""
        if self.step8:
            return self.step8[:100] + "..." if len(self.step8) > 100 else self.step8
        return "No summary provided"