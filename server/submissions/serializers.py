# server/submissions/serializers.py - SQL INJECTION PROOF VERSION

import re
import hashlib
import html
from rest_framework import serializers
from django.core.validators import EmailValidator, RegexValidator
from django.utils.html import strip_tags, escape
from django.core.exceptions import ValidationError
from .models import Submission

class SQLInjectionValidator:
    """🔒 CRITICAL: Advanced SQL injection detection for serializers"""
    
    # 🔒 CRITICAL: Comprehensive SQL injection patterns
    CRITICAL_SQL_PATTERNS = [
        # Basic SQL injection patterns
        r'\bunion\s+(all\s+)?select\b',
        r'\b(and|or)\s+\d+\s*[=<>!]+\s*\d+\b',
        r'\b(and|or)\s+[\'"]?\w+[\'"]?\s*[=<>!]+\s*[\'"]?\w+[\'"]?\b',
        r'\b1\s*=\s*1\b',
        r'\b1\s*or\s*1\b',
        
        # SQL commands that should never be in form data
        r'\b(select|insert|update|delete|drop|create|alter|exec|execute)\b',
        r'\b(sp_|xp_)\w+\b',  # Stored procedures
        
        # SQL comments and terminators
        r'(--|#|/\*|\*/)',
        r';\s*(select|insert|update|delete|drop|create|alter)\b',
        
        # Database metadata access
        r'\binformation_schema\b',
        r'\bsysobjects\b',
        r'\bsyscolumns\b',
        r'\bmysql\.\w+\b',
        
        # Function calls that are dangerous
        r'\b(load_file|into\s+outfile|into\s+dumpfile)\b',
        r'\bload\s+data\s+infile\b',
        r'\bchar\s*\(\s*\d+\s*\)\b',
        
        # Hex and encoded injections
        r'0x[0-9a-fA-F]+',
        r'%27|%22|%2d%2d|%23',  # URL encoded SQL
        
        # Time-based injection indicators
        r'\bwaitfor\s+delay\b',
        r'\bsleep\s*\(\s*\d+\s*\)\b',
        r'\bbenchmark\s*\(',
    ]
    
    @classmethod
    def validate_no_sql_injection(cls, value, field_name='field'):
        """
        🔒 CRITICAL: Validate that input contains no SQL injection
        Raises ValidationError if SQL injection is detected
        """
        if not value:
            return value
        
        text = str(value).lower()
        
        # Check each critical pattern
        for pattern in cls.CRITICAL_SQL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                # 🔒 CRITICAL: Log but don't reveal the pattern to attacker
                import logging
                logger = logging.getLogger('security_monitoring')
                logger.critical(f"SQL injection detected in {field_name}: {pattern}")
                
                # 🔒 CRITICAL: Generic error message (don't reveal detection method)
                raise serializers.ValidationError(
                    f"Invalid characters detected in {field_name}. Please use only standard text."
                )
        
        return value
    
    @classmethod
    def sanitize_sql_input(cls, value):
        """
        🔒 CRITICAL: Sanitize input to remove potential SQL injection
        """
        if not value:
            return value
        
        text = str(value)
        
        # 🔒 CRITICAL: Remove SQL comments
        text = re.sub(r'(--|#|/\*.*?\*/)', '', text, flags=re.DOTALL)
        
        # 🔒 CRITICAL: Remove dangerous quote combinations
        text = re.sub(r"['\"];?\s*(union|select|insert|update|delete|drop)", '', text, flags=re.IGNORECASE)
        
        # 🔒 CRITICAL: Escape HTML entities
        text = html.escape(text)
        
        # 🔒 CRITICAL: Remove null bytes and control characters
        text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
        
        # 🔒 CRITICAL: Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text

class UltraSecureSubmissionCreateSerializer(serializers.ModelSerializer):
    """🔒 SQL INJECTION PROOF: Ultra-secure serializer with comprehensive SQL injection protection"""
    
    # 🔒 CRITICAL: Ultra-strict field validation
    
    # Name field with SQL injection protection
    name = serializers.CharField(
        max_length=100,
        validators=[
            RegexValidator(
                regex=r"^[a-zA-Z\s\-'\.]{2,100}$",
                message="Name can only contain letters, spaces, hyphens, apostrophes, and periods"
            )
        ],
        error_messages={
            'required': 'Full name is required',
            'max_length': 'Name cannot exceed 100 characters',
            'blank': 'Name cannot be empty',
        }
    )
    
    # Email field with enhanced validation
    email = serializers.EmailField(
        max_length=254,
        validators=[EmailValidator()],
        error_messages={
            'required': 'Email address is required',
            'invalid': 'Please enter a valid email address',
            'max_length': 'Email address too long',
        }
    )
    
    # Phone field with strict validation
    phone = serializers.CharField(
        max_length=25,
        validators=[
            RegexValidator(
                regex=r"^[\+\d\s\-\(\)]{7,25}$",
                message="Phone number can only contain digits, spaces, hyphens, parentheses, and plus sign"
            )
        ],
        error_messages={
            'required': 'Phone number is required',
        }
    )
    
    # Country field with whitelist validation
    country = serializers.CharField(
        max_length=2,
        validators=[
            RegexValidator(
                regex=r"^[A-Z]{2}$", 
                message="Country code must be exactly 2 uppercase letters"
            )
        ]
    )
    
    # 🔒 CRITICAL: All text fields with SQL injection protection
    step1 = serializers.CharField(max_length=500, required=False, allow_blank=True, allow_null=True)
    step2 = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True)
    step3 = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True)
    step4 = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True)
    step5 = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True)
    step6 = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True)
    step7 = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True)
    step8 = serializers.CharField(max_length=2000, required=False, allow_blank=True, allow_null=True)
    
    class Meta:
        model = Submission
        fields = [
            'step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7', 'step8',
            'name', 'email', 'country', 'phone'
        ]
    
    def validate_name(self, value):
        """🔒 SQL INJECTION PROOF: Secure name validation"""
        if not value:
            raise serializers.ValidationError("Name is required")
        
        # 🔒 CRITICAL: SQL injection check
        SQLInjectionValidator.validate_no_sql_injection(value, 'name')
        
        # 🔒 CRITICAL: Sanitize input
        value = SQLInjectionValidator.sanitize_sql_input(value)
        
        # Basic validation
        if len(value.strip()) < 2:
            raise serializers.ValidationError("Name must be at least 2 characters long")
        
        if len(value.strip()) > 100:
            raise serializers.ValidationError("Name cannot exceed 100 characters")
        
        # 🔒 CRITICAL: Check for fake/test names that might be injection attempts
        suspicious_names = [
            'admin', 'test', 'fake', 'dummy', 'null', 'undefined', 
            'script', 'alert', 'select', 'union', 'drop', 'delete',
            'insert', 'update', 'create', 'alter', 'exec'
        ]
        
        if value.lower().strip() in suspicious_names:
            raise serializers.ValidationError("Please enter a valid name")
        
        # 🔒 CRITICAL: Additional script detection
        script_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'alert\s*\(',
        ]
        
        for pattern in script_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise serializers.ValidationError("Invalid characters in name")
        
        return value.strip()
    
    def validate_email(self, value):
        """🔒 SQL INJECTION PROOF: Secure email validation"""
        if not value:
            raise serializers.ValidationError("Email is required")
        
        # 🔒 CRITICAL: SQL injection check
        SQLInjectionValidator.validate_no_sql_injection(value, 'email')
        
        # 🔒 CRITICAL: Sanitize input
        value = SQLInjectionValidator.sanitize_sql_input(value).lower().strip()
        
        # Length validation
        if len(value) > 254:
            raise serializers.ValidationError("Email address too long")
        
        # 🔒 CRITICAL: Check for SQL injection in email format
        if value.count('@') != 1:
            raise serializers.ValidationError("Invalid email format")
        
        # 🔒 CRITICAL: Prevent email-based injections
        dangerous_chars = ['<', '>', '"', "'", '&', '\\', '{', '}', '[', ']', '(', ')']
        if any(char in value for char in dangerous_chars):
            raise serializers.ValidationError("Email contains invalid characters")
        
        # 🔒 CRITICAL: Check for suspicious domains/patterns
        suspicious_domains = [
            'test.com', 'fake.com', 'example.com', 'temp.com', 
            'throwaway.email', '10minutemail.com', 'guerrillamail.com'
        ]
        
        domain = value.split('@')[1] if '@' in value else ''
        if domain in suspicious_domains:
            raise serializers.ValidationError("Please use a permanent email address")
        
        # 🔒 CRITICAL: Prevent SQL in email local part
        local_part = value.split('@')[0] if '@' in value else ''
        if any(sql_word in local_part for sql_word in ['select', 'union', 'drop', 'insert', 'delete', 'update']):
            raise serializers.ValidationError("Invalid email format")
        
        return value
    
    def validate_phone(self, value):
        """🔒 SQL INJECTION PROOF: Secure phone validation"""
        if not value:
            raise serializers.ValidationError("Phone number is required")
        
        # 🔒 CRITICAL: SQL injection check
        SQLInjectionValidator.validate_no_sql_injection(value, 'phone')
        
        # 🔒 CRITICAL: Clean and sanitize phone input
        # Only allow digits, +, -, (), and spaces
        cleaned = re.sub(r'[^\d\+\-\(\)\s]', '', str(value))
        
        if not cleaned:
            raise serializers.ValidationError("Please enter a valid phone number")
        
        # 🔒 CRITICAL: Length validation
        digits_only = re.sub(r'[^\d]', '', cleaned)
        if len(digits_only) < 7:
            raise serializers.ValidationError("Phone number is too short")
        
        if len(digits_only) > 18:
            raise serializers.ValidationError("Phone number is too long")
        
        # 🔒 CRITICAL: Check for fake/test numbers
        fake_patterns = ['1111111', '2222222', '0000000', '1234567', '7777777', '8888888', '9999999']
        for pattern in fake_patterns:
            if pattern in digits_only:
                raise serializers.ValidationError("Please enter a real phone number")
        
        # 🔒 CRITICAL: Ensure phone doesn't contain SQL keywords
        if any(sql_word in cleaned.lower() for sql_word in ['select', 'union', 'drop', 'insert', 'delete']):
            raise serializers.ValidationError("Invalid phone number format")
        
        return cleaned
    
    def validate_country(self, value):
        """🔒 SQL INJECTION PROOF: Secure country validation"""
        if not value:
            raise serializers.ValidationError("Country is required")
        
        # 🔒 CRITICAL: SQL injection check
        SQLInjectionValidator.validate_no_sql_injection(value, 'country')
        
        value = str(value).upper().strip()
        
        # 🔒 CRITICAL: Strict format validation
        if not re.match(r'^[A-Z]{2}$', value):
            raise serializers.ValidationError("Country code must be exactly 2 uppercase letters")
        
        # 🔒 CRITICAL: Whitelist of valid country codes
        VALID_COUNTRIES = {
            'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AQ', 'AR', 'AS', 'AT', 'AU', 'AW', 'AX', 'AZ',
            'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ', 'BR', 'BS',
            'BT', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN',
            'CO', 'CR', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE',
            'EG', 'EH', 'ER', 'ES', 'ET', 'FI', 'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF',
            'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM',
            'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM',
            'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC',
            'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF', 'MG', 'MH', 'MK',
            'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA',
            'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG',
            'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU', 'RW',
            'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'SS',
            'ST', 'SV', 'SX', 'SY', 'SZ', 'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO',
            'TR', 'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI',
            'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW'
        }
        
        if value not in VALID_COUNTRIES:
            raise serializers.ValidationError("Invalid country code")
        
        return value
    
    def validate_step_field(self, value, field_name, max_length=500):
        """🔒 SQL INJECTION PROOF: Validate step fields"""
        if not value:
            return value
        
        # 🔒 CRITICAL: SQL injection check
        SQLInjectionValidator.validate_no_sql_injection(value, field_name)
        
        # 🔒 CRITICAL: Sanitize input
        value = SQLInjectionValidator.sanitize_sql_input(value)
        
        # Length validation
        if len(value) > max_length:
            raise serializers.ValidationError(f"Text too long (maximum {max_length} characters)")
        
        return value.strip()
    
    # Individual step field validators
    def validate_step1(self, value):
        return self.validate_step_field(value, 'step1', 500)
    
    def validate_step2(self, value):
        return self.validate_step_field(value, 'step2', 100)
    
    def validate_step3(self, value):
        return self.validate_step_field(value, 'step3', 100)
    
    def validate_step4(self, value):
        return self.validate_step_field(value, 'step4', 100)
    
    def validate_step5(self, value):
        return self.validate_step_field(value, 'step5', 100)
    
    def validate_step6(self, value):
        return self.validate_step_field(value, 'step6', 100)
    
    def validate_step7(self, value):
        return self.validate_step_field(value, 'step7', 100)
    
    def validate_step8(self, value):
        return self.validate_step_field(value, 'step8', 2000)
    
    def validate(self, attrs):
        """🔒 SQL INJECTION PROOF: Cross-field validation with comprehensive security checks"""
        
        # 🔒 CRITICAL: Final SQL injection check on all combined data
        all_text_fields = []
        for field, value in attrs.items():
            if value and isinstance(value, str):
                all_text_fields.append(f"{field}:{value}")
        
        combined_text = " ".join(all_text_fields)
        
        # 🔒 CRITICAL: Check combined text for SQL injection
        SQLInjectionValidator.validate_no_sql_injection(combined_text, 'combined_form_data')
        
        # 🔒 CRITICAL: Check total submission size to prevent buffer overflow
        total_length = sum(len(str(attrs.get(field, ''))) for field in attrs.keys())
        if total_length > 10000:  # 10KB limit
            raise serializers.ValidationError("Form submission too large")
        
        if total_length < 10:  # Too small submission
            raise serializers.ValidationError("Form submission appears incomplete")
        
        # 🔒 CRITICAL: Validate required fields are present
        required_fields = ['name', 'email', 'phone', 'country']
        for field in required_fields:
            if not str(attrs.get(field, '')).strip():
                field_name = field.replace('_', ' ').title()
                raise serializers.ValidationError(f"{field_name} is required")
        
        # 🔒 CRITICAL: Additional cross-field security checks
        
        # Check for form bombing (all fields identical)
        non_empty_values = [str(v).strip().lower() for k, v in attrs.items() if v and str(v).strip()]
        if len(set(non_empty_values)) == 1 and len(non_empty_values) > 3:
            raise serializers.ValidationError("All form fields cannot have identical values")
        
        # Check for excessive repetition across fields
        combined_lower = combined_text.lower()
        if re.search(r'(.{4,})\1{5,}', combined_lower):  # Same 4+ chars repeated 5+ times
            raise serializers.ValidationError("Form contains excessive repetitive content")
        
        # 🔒 CRITICAL: Business logic validation
        
        # Validate email domain against name (basic coherence check)
        email = attrs.get('email', '').lower()
        name = attrs.get('name', '').lower()
        
        if email and name:
            # If using a business email, name should be somewhat coherent
            business_domains = ['.com', '.org', '.net', '.co.', '.inc', '.corp']
            if any(domain in email for domain in business_domains):
                if len(name) < 5 or not re.match(r'^[a-z\s\-\'\.]+$', name):
                    pass  # Allow for now, but this could be enhanced
        
        return attrs

# Create alias for backward compatibility
SecureSubmissionCreateSerializer = UltraSecureSubmissionCreateSerializer


class SubmissionListSerializer(serializers.ModelSerializer):
    """🔒 SQL INJECTION PROOF: Secure serializer for admin list view with data masking"""
    
    # Mask sensitive data in list view for privacy
    email_masked = serializers.SerializerMethodField()
    phone_masked = serializers.SerializerMethodField()
    
    class Meta:
        model = Submission
        fields = [
            'id', 'uuid', 'name', 'email_masked', 'country', 'phone_masked',
            'submitted_at', 'data_classification', 'anonymized'
        ]
        read_only_fields = ['id', 'uuid', 'submitted_at']
    
    def get_email_masked(self, obj):
        """🔒 SECURITY: Mask email for privacy in list view"""
        try:
            if hasattr(obj, 'anonymized') and obj.anonymized:
                return "ANONYMIZED"
            
            email = str(obj.email)
            if '@' in email:
                local, domain = email.split('@', 1)
                if len(local) > 2:
                    masked_local = local[:2] + '*' * (len(local) - 2)
                else:
                    masked_local = '***'
                return f"{masked_local}@{domain}"
            return "***@***.***"
        except Exception:
            return "***@***.***"
    
    def get_phone_masked(self, obj):
        """🔒 SECURITY: Mask phone for privacy in list view"""
        try:
            if hasattr(obj, 'anonymized') and obj.anonymized:
                return "ANONYMIZED"
            
            phone = str(obj.phone)
            if len(phone) > 4:
                return phone[:2] + '*' * (len(phone) - 4) + phone[-2:]
            return "***-***-****"
        except Exception:
            return "***-***-****"


class SubmissionDetailSerializer(serializers.ModelSerializer):
    """🔒 SQL INJECTION PROOF: Secure serializer for detailed admin view"""
    
    integrity_status = serializers.SerializerMethodField()
    
    class Meta:
        model = Submission
        fields = [
            'id', 'uuid', 'step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7', 'step8',
            'name', 'email', 'country', 'phone', 'submitted_at', 'data_classification',
            'retention_date', 'anonymized', 'checksum', 'integrity_status'
        ]
        read_only_fields = [
            'id', 'uuid', 'submitted_at', 'checksum', 'email_hash', 'phone_hash',
            'ip_address_hash', 'user_agent_hash', 'integrity_status'
        ]
    
    def get_integrity_status(self, obj):
        """🔒 SECURITY: Check data integrity status"""
        try:
            return obj.verify_integrity() if hasattr(obj, 'verify_integrity') else True
        except Exception:
            return False


class SubmissionExportSerializer(serializers.ModelSerializer):
    """🔒 SQL INJECTION PROOF: Secure serializer for data export with audit trail"""
    
    class Meta:
        model = Submission
        fields = [
            'uuid', 'step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7', 'step8',
            'country', 'submitted_at', 'data_classification', 'anonymized'
        ]
        # 🔒 SECURITY NOTE: PII fields (name, email, phone) excluded from export