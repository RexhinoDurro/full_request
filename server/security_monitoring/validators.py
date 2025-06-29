# security_monitoring/validators.py
from django.contrib.auth.password_validation import BasePasswordValidator
from django.core.exceptions import ValidationError
import re

class CustomPasswordValidator(BasePasswordValidator):
    """Enhanced password validator"""
    
    def validate(self, password, user=None):
        if len(password) < 12:
            raise ValidationError("Password must be at least 12 characters long.")
        
        if not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        
        if not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain at least one lowercase letter.")
        
        if not re.search(r'\d', password):
            raise ValidationError("Password must contain at least one digit.")
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            raise ValidationError("Password must contain at least one special character.")
        
        # Check for common patterns
        if re.search(r'(.)\1{2,}', password):
            raise ValidationError("Password cannot contain more than 2 consecutive identical characters.")
        
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            raise ValidationError("Password cannot contain sequential numbers.")
        
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            raise ValidationError("Password cannot contain sequential letters.")

    def get_help_text(self):
        return (
            "Your password must contain at least 12 characters with uppercase, "
            "lowercase, numbers, and special characters. Avoid sequential or "
            "repetitive patterns."
        )