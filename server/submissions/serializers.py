# submissions/serializers.py - Enhanced with security
from rest_framework import serializers
from django.core.validators import EmailValidator, RegexValidator
from django.utils.html import strip_tags
import bleach
import re
from .models import Submission

class SecureSubmissionCreateSerializer(serializers.ModelSerializer):
    """Ultra-secure serializer for creating submissions"""
    
    # Define allowed HTML tags (none for maximum security)
    ALLOWED_TAGS = []
    ALLOWED_ATTRIBUTES = {}
    
    # Custom validators
    name_validator = RegexValidator(
        regex=r"^[a-zA-Z\s\-'\.]{2,100}$",
        message="Name can only contain letters, spaces, hyphens, apostrophes, and periods (2-100 characters)"
    )
    
    phone_validator = RegexValidator(
        regex=r"^\+?[\d\s\-\(\)]{7,20}$",
        message="Phone number must be 7-20 characters and contain only digits, spaces, hyphens, and parentheses"
    )
    
    # Enhanced field definitions
    name = serializers.CharField(
        max_length=100,
        validators=[name_validator],
        error_messages={
            'required': 'Name is required',
            'max_length': 'Name cannot exceed 100 characters',
        }
    )
    
    email = serializers.EmailField(
        validators=[EmailValidator()],
        error_messages={
            'required': 'Email is required',
            'invalid': 'Please enter a valid email address',
        }
    )
    
    phone = serializers.CharField(
        max_length=20,
        validators=[phone_validator],
        error_messages={
            'required': 'Phone number is required',
        }
    )
    
    country = serializers.CharField(
        max_length=2,
        validators=[RegexValidator(regex=r"^[A-Z]{2}$", message="Country code must be 2 uppercase letters")]
    )
    
    # Text field validators
    step1 = serializers.CharField(max_length=500, required=False, allow_blank=True)
    step2 = serializers.CharField(max_length=100, required=False, allow_blank=True)
    step3 = serializers.CharField(max_length=100, required=False, allow_blank=True)
    step4 = serializers.CharField(max_length=100, required=False, allow_blank=True)
    step5 = serializers.CharField(max_length=100, required=False, allow_blank=True)
    step6 = serializers.CharField(max_length=100, required=False, allow_blank=True)
    step7 = serializers.CharField(max_length=100, required=False, allow_blank=True)
    step8 = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    
    class Meta:
        model = Submission
        fields = [
            'step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7', 'step8',
            'name', 'email', 'country', 'phone'
        ]
    
    def validate_email(self, value):
        """Enhanced email validation"""
        if not value:
            raise serializers.ValidationError("Email is required")
        
        # Convert to lowercase for consistency
        value = value.lower().strip()
        
        # Check for dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '\\', '/', '(', ')', '{', '}']
        if any(char in value for char in dangerous_chars):
            raise serializers.ValidationError("Email contains invalid characters")
        
        # Additional email validation
        if len(value) > 254:  # RFC 5321 limit
            raise serializers.ValidationError("Email address too long")
        
        # Check for multiple @ symbols
        if value.count('@') != 1:
            raise serializers.ValidationError("Invalid email format")
        
        return value
    
    def validate_name(self, value):
        """Enhanced name validation"""
        if not value:
            raise serializers.ValidationError("Name is required")
        
        # Strip HTML and dangerous content
        value = self.sanitize_input(value)
        
        if len(value.strip()) < 2:
            raise serializers.ValidationError("Name must be at least 2 characters long")
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'<script',
            r'javascript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'document\.',
            r'window\.',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise serializers.ValidationError("Name contains invalid content")
        
        return value.strip()
    
    def validate_phone(self, value):
        """Enhanced phone validation"""
        if not value:
            raise serializers.ValidationError("Phone number is required")
        
        # Remove all non-alphanumeric except +, -, (, ), space
        cleaned = re.sub(r'[^\d\+\-\(\)\s]', '', value)
        
        if not cleaned:
            raise serializers.ValidationError("Invalid phone number format")
        
        return cleaned.strip()
    
    def sanitize_input(self, value):
        """Sanitize input to prevent XSS and injection attacks"""
        if not value:
            return value
        
        # Strip HTML tags
        value = strip_tags(value)
        
        # Use bleach for additional cleaning
        value = bleach.clean(
            value,
            tags=self.ALLOWED_TAGS,
            attributes=self.ALLOWED_ATTRIBUTES,
            strip=True
        )
        
        # Remove null bytes and other dangerous characters
        value = value.replace('\x00', '').replace('\r', '').replace('\n', ' ')
        
        # Limit length to prevent buffer overflow attacks
        if len(value) > 2000:
            value = value[:2000]
        
        return value
    
    def validate(self, attrs):
        """Cross-field validation"""
        # Sanitize all text inputs
        for field in ['step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7', 'step8']:
            if field in attrs and attrs[field]:
                attrs[field] = self.sanitize_input(attrs[field])
        
        # Check for suspicious patterns across all fields
        all_text = ' '.join([
            str(attrs.get(field, '')) for field in attrs.keys()
        ])
        
        # SQL injection detection
        sql_patterns = [
            r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b',
            r'\bunion\b.*\bselect\b',
            r'\bor\b.*=.*',
            r'(--|#|\/\*)',
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                raise serializers.ValidationError("Submission contains suspicious content")
        
        # XSS detection
        xss_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'eval\s*\(',
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                raise serializers.ValidationError("Submission contains suspicious content")
        
        return attrs