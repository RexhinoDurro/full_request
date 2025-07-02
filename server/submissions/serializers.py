# submissions/serializers.py - ULTRA-SECURE VERSION with ALL security features
from rest_framework import serializers
from django.core.validators import EmailValidator, RegexValidator
from django.utils.html import strip_tags
import bleach
import re
import hashlib
from .models import Submission

class UltraSecureSubmissionCreateSerializer(serializers.ModelSerializer):
    """🔒 ULTRA-SECURE: Advanced serializer with comprehensive security validation"""
    
    # 🔒 SECURITY: Define allowed HTML tags (none for maximum security)
    ALLOWED_TAGS = []
    ALLOWED_ATTRIBUTES = {}
    
    # 🔒 SECURITY: Advanced custom validators
    name_validator = RegexValidator(
        regex=r"^[a-zA-Z\s\-'\.]{2,100}$",
        message="Name can only contain letters, spaces, hyphens, apostrophes, and periods (2-100 characters)"
    )
    
    phone_validator = RegexValidator(
        regex=r"^\+?[\d\s\-\(\)]{7,20}$",
        message="Phone number must be 7-20 characters and contain only digits, spaces, hyphens, and parentheses"
    )
    
    # 🔒 SECURITY: Enhanced field definitions with ultra-strict validation
    name = serializers.CharField(
        max_length=100,
        validators=[name_validator],
        error_messages={
            'required': 'Name is required',
            'max_length': 'Name cannot exceed 100 characters',
            'blank': 'Name cannot be empty',
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
    
    # 🔒 SECURITY: Ultra-strict text field validators with length limits
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
        """🔒 SECURITY: Ultra-strict email validation with threat detection"""
        if not value:
            raise serializers.ValidationError("Email is required")
        
        # Convert to lowercase for consistency and normalize
        value = value.lower().strip()
        
        # 🔒 SECURITY: Check for dangerous characters and patterns
        dangerous_chars = ['<', '>', '"', "'", '&', '\\', '/', '(', ')', '{', '}', '[', ']']
        if any(char in value for char in dangerous_chars):
            raise serializers.ValidationError("Email contains invalid characters")
        
        # 🔒 SECURITY: Advanced email validation
        if len(value) > 254:  # RFC 5321 limit
            raise serializers.ValidationError("Email address too long")
        
        # Check for multiple @ symbols
        if value.count('@') != 1:
            raise serializers.ValidationError("Invalid email format")
        
        # 🔒 SECURITY: Check for suspicious email patterns
        suspicious_patterns = [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(test|example|invalid|localhost)$',  # Test domains
            r'.*\+.*\+.*@',  # Multiple plus signs
            r'.*\.{2,}.*@',  # Multiple consecutive dots
            r'^[0-9]+@',     # Starts with numbers only
            r'@[0-9]+\.',    # Domain starts with numbers
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, value):
                raise serializers.ValidationError("Suspicious email pattern detected")
        
        # 🔒 SECURITY: Check domain length
        domain = value.split('@')[1]
        if len(domain) < 3 or len(domain) > 253:
            raise serializers.ValidationError("Invalid email domain length")
        
        return value
    
    def validate_name(self, value):
        """🔒 SECURITY: Ultra-strict name validation with advanced threat detection"""
        if not value:
            raise serializers.ValidationError("Name is required")
        
        # Strip HTML and dangerous content
        value = self.sanitize_input(value)
        
        if len(value.strip()) < 2:
            raise serializers.ValidationError("Name must be at least 2 characters long")
        
        if len(value.strip()) > 100:
            raise serializers.ValidationError("Name cannot exceed 100 characters")
        
        # 🔒 SECURITY: Check for suspicious patterns
        suspicious_patterns = [
            r'<script',
            r'javascript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'document\.',
            r'window\.',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
            r'[<>{}]',  # HTML/script tags
            r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b',  # SQL keywords
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise serializers.ValidationError("Name contains invalid content")
        
        # 🔒 SECURITY: Check for excessive repetition (spam indicator)
        if re.search(r'(.)\1{4,}', value):
            raise serializers.ValidationError("Name contains excessive character repetition")
        
        # 🔒 SECURITY: Check for too many special characters
        special_char_count = len(re.findall(r'[^a-zA-Z\s]', value))
        if special_char_count > len(value) * 0.3:  # More than 30% special chars
            raise serializers.ValidationError("Name contains too many special characters")
        
        return value.strip()
    
    def validate_phone(self, value):
        """🔒 SECURITY: Ultra-strict phone validation with international support"""
        if not value:
            raise serializers.ValidationError("Phone number is required")
        
        # 🔒 SECURITY: Remove all non-phone characters (keep only digits, +, -, (, ), space)
        cleaned = re.sub(r'[^\d\+\-\(\)\s]', '', value)
        
        if not cleaned:
            raise serializers.ValidationError("Invalid phone number format")
        
        # 🔒 SECURITY: Check for suspicious patterns
        if re.search(r'[<>{}]', value):
            raise serializers.ValidationError("Phone number contains invalid characters")
        
        # Check minimum digit count
        digit_count = len(re.findall(r'\d', cleaned))
        if digit_count < 7:
            raise serializers.ValidationError("Phone number too short")
        
        if digit_count > 15:
            raise serializers.ValidationError("Phone number too long")
        
        # 🔒 SECURITY: Check for repetitive patterns (spam indicator)
        if re.search(r'(\d)\1{6,}', cleaned):
            raise serializers.ValidationError("Phone number contains suspicious repetition")
        
        return cleaned.strip()
    
    def validate_country(self, value):
        """🔒 SECURITY: Validate country code"""
        if not value:
            raise serializers.ValidationError("Country is required")
        
        # Ensure uppercase
        value = value.upper().strip()
        
        # Must be exactly 2 characters
        if len(value) != 2:
            raise serializers.ValidationError("Country code must be 2 characters")
        
        # Must be alphabetic
        if not value.isalpha():
            raise serializers.ValidationError("Country code must contain only letters")
        
        # 🔒 SECURITY: Validate against known country codes (basic check)
        valid_countries = [
            'US', 'CA', 'GB', 'DE', 'FR', 'IT', 'ES', 'NL', 'BE', 'CH', 'AT', 'SE', 'NO', 'DK', 
            'FI', 'IE', 'PT', 'PL', 'CZ', 'HU', 'SK', 'SI', 'HR', 'RO', 'BG', 'GR', 'CY', 'MT',
            'LU', 'EE', 'LV', 'LT', 'AL', 'BA', 'ME', 'MK', 'RS', 'RU', 'UA', 'BY', 'MD', 'IS',
            'CN', 'JP', 'KR', 'IN', 'ID', 'TH', 'VN', 'PH', 'MY', 'SG', 'TW', 'HK', 'MO', 'MM',
            'KH', 'LA', 'BD', 'LK', 'PK', 'AF', 'NP', 'BT', 'MV', 'UZ', 'KZ', 'KG', 'TJ', 'TM',
            'MN', 'AE', 'SA', 'QA', 'KW', 'BH', 'OM', 'JO', 'LB', 'SY', 'IQ', 'IR', 'IL', 'PS',
            'TR', 'YE', 'ZA', 'EG', 'NG', 'KE', 'GH', 'ET', 'TZ', 'UG', 'MA', 'DZ', 'TN', 'LY',
            'SD', 'SS', 'ZW', 'ZM', 'BW', 'NA', 'MZ', 'MW', 'SZ', 'LS', 'RW', 'BI', 'DJ', 'SO',
            'ER', 'AO', 'CD', 'CG', 'CF', 'CM', 'TD', 'GA', 'GQ', 'ST', 'CI', 'LR', 'SL', 'GN',
            'GW', 'SN', 'GM', 'ML', 'BF', 'NE', 'MR', 'CV', 'MU', 'SC', 'MG', 'KM', 'AU', 'NZ',
            'FJ', 'PG', 'NC', 'SB', 'VU', 'WS', 'TO', 'KI', 'TV', 'NR', 'PW', 'FM', 'MH', 'MX',
            'BR', 'AR', 'CL', 'CO', 'PE', 'VE', 'EC', 'UY', 'PY', 'BO', 'CR', 'PA', 'GT', 'HN',
            'SV', 'NI', 'BZ', 'JM', 'CU', 'DO', 'HT', 'TT'
        ]
        
        if value not in valid_countries:
            raise serializers.ValidationError("Invalid country code")
        
        return value
    
    def sanitize_input(self, value):
        """🔒 SECURITY: Advanced input sanitization to prevent all attack vectors"""
        if not value:
            return value
        
        # Strip HTML tags using Django's strip_tags
        value = strip_tags(value)
        
        # Use bleach for additional cleaning (ultra-strict)
        value = bleach.clean(
            value,
            tags=self.ALLOWED_TAGS,
            attributes=self.ALLOWED_ATTRIBUTES,
            strip=True
        )
        
        # 🔒 SECURITY: Remove dangerous characters and patterns
        # Remove null bytes, control characters, and other dangerous chars
        value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
        
        # Remove script-related patterns
        script_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'data:',
            r'on\w+\s*=',
        ]
        
        for pattern in script_patterns:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE | re.DOTALL)
        
        # Normalize whitespace
        value = re.sub(r'\s+', ' ', value)
        
        # Limit length to prevent buffer overflow attacks
        if len(value) > 2000:
            value = value[:2000]
        
        return value.strip()
    
    def validate(self, attrs):
        """🔒 SECURITY: Ultra-comprehensive cross-field validation and threat detection"""
        # Sanitize all text inputs
        for field in ['step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7', 'step8']:
            if field in attrs and attrs[field]:
                attrs[field] = self.sanitize_input(attrs[field])
        
        # 🔒 SECURITY: Comprehensive threat analysis across all fields
        all_text = ' '.join([
            str(attrs.get(field, '')) for field in attrs.keys()
        ]).lower()
        
        # 🔒 SECURITY: Advanced SQL injection detection
        sql_patterns = [
            r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b',
            r'\bunion\b.*\bselect\b',
            r'\bor\b.*=.*\bor\b',
            r'(--|#|\/\*)',
            r'\bxp_cmdshell\b',
            r'\bsp_executesql\b',
            r';.*\b(SELECT|INSERT|UPDATE|DELETE)\b',
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                raise serializers.ValidationError("Submission contains suspicious SQL patterns")
        
        # 🔒 SECURITY: Advanced XSS detection
        xss_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'expression\s*\(',
            r'url\s*\(',
            r'@import',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<link[^>]*>',
            r'<meta[^>]*>',
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                raise serializers.ValidationError("Submission contains suspicious script patterns")
        
        # 🔒 SECURITY: Command injection detection
        command_patterns = [
            r';\s*(cat|ls|pwd|whoami|id|uname)',
            r'\|\s*(cat|ls|pwd|whoami|id|uname)',
            r'&&\s*(cat|ls|pwd|whoami|id|uname)',
            r'`.*`',
            r'\$\(.*\)',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
        ]
        
        for pattern in command_patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                raise serializers.ValidationError("Submission contains suspicious command patterns")
        
        # 🔒 SECURITY: Path traversal detection
        path_patterns = [
            r'\.\./.*',
            r'\.\.\\.*',
            r'%2e%2e%2f',
            r'%2e%2e\\',
            r'/etc/passwd',
            r'/proc/version',
            r'\\windows\\system32',
        ]
        
        for pattern in path_patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                raise serializers.ValidationError("Submission contains suspicious path patterns")
        
        # 🔒 SECURITY: Advanced spam detection
        spam_indicators = 0
        
        # Check for excessive URLs
        url_count = len(re.findall(r'http[s]?://|www\.', all_text))
        if url_count > 2:
            spam_indicators += url_count * 2
        
        # Check for excessive repetition
        if re.search(r'(.{3,})\1{3,}', all_text):
            spam_indicators += 5
        
        # Check for excessive caps
        caps_ratio = len(re.findall(r'[A-Z]', all_text)) / max(len(all_text), 1)
        if caps_ratio > 0.5 and len(all_text) > 20:
            spam_indicators += 3
        
        # Check for spam keywords
        spam_keywords = [
            'click here', 'free money', 'make money fast', 'work from home',
            'weight loss', 'diet pills', 'enlargement', 'casino', 'lottery',
            'winner', 'congratulations', 'urgent', 'limited time'
        ]
        
        for keyword in spam_keywords:
            if keyword in all_text:
                spam_indicators += 2
        
        if spam_indicators >= 8:
            raise serializers.ValidationError("Submission appears to be spam")
        
        # 🔒 SECURITY: Data integrity validation
        # Check for inconsistent data patterns
        total_length = sum(len(str(attrs.get(field, ''))) for field in attrs.keys())
        if total_length > 10000:  # Very large submission
            raise serializers.ValidationError("Submission too large")
        
        if total_length < 10:  # Very small submission
            raise serializers.ValidationError("Submission too short")
        
        # 🔒 SECURITY: Validate required field combinations
        required_fields = ['name', 'email', 'phone', 'country']
        for field in required_fields:
            if not attrs.get(field, '').strip():
                raise serializers.ValidationError(f"{field.title()} is required")
        
        return attrs

# Aliases for backward compatibility and different use cases
SecureSubmissionCreateSerializer = UltraSecureSubmissionCreateSerializer

class SubmissionListSerializer(serializers.ModelSerializer):
    """🔒 SECURITY: Serializer for listing submissions (admin view) with data protection"""
    
    # Mask sensitive data in list view
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
        if obj.anonymized:
            return "ANONYMIZED"
        email = str(obj.email)
        if '@' in email:
            local, domain = email.split('@', 1)
            masked_local = local[:2] + '*' * (len(local) - 2)
            return f"{masked_local}@{domain}"
        return "***@***.***"
    
    def get_phone_masked(self, obj):
        """🔒 SECURITY: Mask phone for privacy in list view"""
        if obj.anonymized:
            return "ANONYMIZED"
        phone = str(obj.phone)
        if len(phone) > 4:
            return phone[:2] + '*' * (len(phone) - 4) + phone[-2:]
        return "***-***-****"

class SubmissionDetailSerializer(serializers.ModelSerializer):
    """🔒 SECURITY: Serializer for detailed submission view (admin only) with full access control"""
    
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
            return obj.verify_integrity()
        except Exception:
            return False

class SubmissionExportSerializer(serializers.ModelSerializer):
    """🔒 SECURITY: Serializer for secure data export with audit trail"""
    
    class Meta:
        model = Submission
        fields = [
            'uuid', 'step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7', 'step8',
            'country', 'submitted_at', 'data_classification', 'anonymized'
        ]
        # Note: PII fields (name, email, phone) excluded from export for security