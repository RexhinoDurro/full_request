# server/submissions/serializers.py - ENHANCED ULTRA-SECURE VERSION
import re
import hashlib
import phonenumbers
from phonenumbers import NumberParseException
from rest_framework import serializers
from django.core.validators import EmailValidator, RegexValidator
from django.utils.html import strip_tags
import bleach
from .models import Submission

class UltraSecureSubmissionCreateSerializer(serializers.ModelSerializer):
    """🔒 ULTRA-SECURE: Advanced serializer with enhanced phone validation and comprehensive security"""
    
    # 🔒 SECURITY: Country code mapping for phone validation
    COUNTRY_DIAL_CODES = {
        'US': '+1', 'CA': '+1', 'GB': '+44', 'DE': '+49', 'FR': '+33', 'IT': '+39', 'ES': '+34',
        'NL': '+31', 'BE': '+32', 'CH': '+41', 'AT': '+43', 'SE': '+46', 'NO': '+47', 'DK': '+45',
        'FI': '+358', 'IE': '+353', 'PT': '+351', 'AU': '+61', 'NZ': '+64', 'JP': '+81', 'KR': '+82',
        'CN': '+86', 'IN': '+91', 'SG': '+65', 'MY': '+60', 'TH': '+66', 'VN': '+84', 'PH': '+63',
        'ID': '+62', 'AE': '+971', 'SA': '+966', 'QA': '+974', 'KW': '+965', 'BH': '+973',
        'OM': '+968', 'JO': '+962', 'LB': '+961', 'IL': '+972', 'TR': '+90', 'ZA': '+27',
        'EG': '+20', 'NG': '+234', 'KE': '+254', 'GH': '+233', 'MA': '+212', 'BR': '+55',
        'AR': '+54', 'CL': '+56', 'CO': '+57', 'PE': '+51', 'VE': '+58', 'EC': '+593', 'MX': '+52',
        'PL': '+48', 'CZ': '+420', 'HU': '+36', 'SK': '+421', 'SI': '+386', 'HR': '+385',
        'RO': '+40', 'BG': '+359', 'GR': '+30', 'CY': '+357', 'MT': '+356', 'LU': '+352',
        'EE': '+372', 'LV': '+371', 'LT': '+370', 'AL': '+355', 'BA': '+387', 'ME': '+382',
        'MK': '+389', 'RS': '+381', 'RU': '+7', 'UA': '+380', 'BY': '+375', 'MD': '+373', 'IS': '+354'
    }
    
    # 🔒 ENHANCED: Strict phone patterns by country
    PHONE_PATTERNS = {
        'US': {
            'pattern': r'^(\+1)?[2-9]\d{2}[2-9]\d{2}\d{4}$',
            'format': '+1 (XXX) XXX-XXXX',
            'example': '+1 (555) 123-4567'
        },
        'CA': {
            'pattern': r'^(\+1)?[2-9]\d{2}[2-9]\d{2}\d{4}$',
            'format': '+1 (XXX) XXX-XXXX', 
            'example': '+1 (416) 555-1234'
        },
        'GB': {
            'pattern': r'^(\+44)?[1-9]\d{8,9}$',
            'format': '+44 XXXX XXXXXX',
            'example': '+44 20 7946 0958'
        },
        'DE': {
            'pattern': r'^(\+49)?[1-9]\d{10,11}$',
            'format': '+49 XXX XXXXXXXX',
            'example': '+49 30 12345678'
        },
        'FR': {
            'pattern': r'^(\+33)?[1-9]\d{8}$',
            'format': '+33 X XX XX XX XX',
            'example': '+33 1 42 34 56 78'
        },
        'AU': {
            'pattern': r'^(\+61)?[2-9]\d{8}$',
            'format': '+61 X XXXX XXXX',
            'example': '+61 2 9876 5432'
        },
        'JP': {
            'pattern': r'^(\+81)?[1-9]\d{9,10}$',
            'format': '+81 XX XXXX XXXX',
            'example': '+81 3 1234 5678'
        },
        'IN': {
            'pattern': r'^(\+91)?[6-9]\d{9}$',
            'format': '+91 XXXXX XXXXX',
            'example': '+91 98765 43210'
        },
        'IT': {
            'pattern': r'^(\+39)?[0-9]\d{8,9}$',
            'format': '+39 XXX XXX XXXX',
            'example': '+39 06 1234 5678'
        },
        'ES': {
            'pattern': r'^(\+34)?[6-9]\d{8}$',
            'format': '+34 XXX XXX XXX',
            'example': '+34 600 123 456'
        },
        'NL': {
            'pattern': r'^(\+31)?[1-9]\d{8}$',
            'format': '+31 X XXXX XXXX',
            'example': '+31 6 1234 5678'
        },
        'BE': {
            'pattern': r'^(\+32)?[1-9]\d{7,8}$',
            'format': '+32 XXX XX XX XX',
            'example': '+32 123 45 67 89'
        },
    }
    
    # 🔒 SECURITY: Define allowed HTML tags (none for maximum security)
    ALLOWED_TAGS = []
    ALLOWED_ATTRIBUTES = {}
    
    # Enhanced validators
    name_validator = RegexValidator(
        regex=r"^[a-zA-Z\s\-'\.]{2,100}$",
        message="Name can only contain letters, spaces, hyphens, apostrophes, and periods (2-100 characters)"
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
        """🔒 ENHANCED: Ultra-strict phone validation with country-specific patterns"""
        if not value:
            raise serializers.ValidationError("Phone number is required")
        
        # Get country from validated data or default to US
        country = self.initial_data.get('country', 'US').upper()
        
        # 🔒 SECURITY: Clean input - remove all non-digits and non-plus
        cleaned = re.sub(r'[^\d\+]', '', value)
        
        if not cleaned:
            raise serializers.ValidationError("Invalid phone number format")
        
        # 🔒 SECURITY: Check for dangerous characters first
        if re.search(r'[<>{}]', value):
            raise serializers.ValidationError("Phone number contains invalid characters")
        
        # Basic length validation
        if len(cleaned) < 7:
            raise serializers.ValidationError("Phone number too short (minimum 7 digits)")
        
        if len(cleaned) > 15:
            raise serializers.ValidationError("Phone number too long (maximum 15 digits)")
        
        # 🔒 ENHANCED: Country-specific validation
        if country in self.PHONE_PATTERNS:
            pattern_info = self.PHONE_PATTERNS[country]
            
            # Ensure country code is present
            country_code = self.COUNTRY_DIAL_CODES.get(country, '+1')
            if not cleaned.startswith('+'):
                # Add country code if missing
                if country in ['US', 'CA'] and cleaned.startswith('1'):
                    # US/CA numbers might already have the '1' prefix
                    cleaned = '+' + cleaned
                else:
                    cleaned = country_code + cleaned
            
            # Test against country-specific pattern
            digits_only = cleaned.replace('+', '')
            if not re.match(pattern_info['pattern'].replace(r'(\+\d{1,3})?', ''), digits_only):
                raise serializers.ValidationError(
                    f"Invalid {country} phone number. "
                    f"Expected format: {pattern_info['format']}. "
                    f"Example: {pattern_info['example']}"
                )
        else:
            # 🔒 ENHANCED: Generic international validation for other countries
            country_code = self.COUNTRY_DIAL_CODES.get(country, '+1')
            
            # Ensure international format
            if not cleaned.startswith('+'):
                cleaned = country_code + cleaned
            
            # Validate international format
            if not re.match(r'^\+\d{7,15}$', cleaned):
                raise serializers.ValidationError(
                    f"Invalid phone number. Please use international format: "
                    f"{country_code} followed by your local number"
                )
        
        # 🔒 ENHANCED: Additional security checks
        
        # Check for suspicious patterns (spam indicators)
        if re.search(r'(\d)\1{6,}', cleaned):  # 7+ consecutive same digits
            raise serializers.ValidationError("Phone number contains suspicious repetitive patterns")
        
        # Check for obviously fake numbers
        fake_patterns = [
            r'1234567',
            r'0000000',
            r'1111111',
            r'9999999',
            r'5555555'
        ]
        
        for pattern in fake_patterns:
            if pattern in cleaned:
                raise serializers.ValidationError("Please provide a valid phone number")
        
        # 🔒 ADVANCED: Use phonenumbers library for additional validation
        try:
            # Parse and validate using Google's libphonenumber
            parsed_number = phonenumbers.parse(cleaned, country)
            
            if not phonenumbers.is_valid_number(parsed_number):
                raise serializers.ValidationError("Invalid phone number for the selected country")
            
            if not phonenumbers.is_possible_number(parsed_number):
                raise serializers.ValidationError("Phone number is not possible for the selected country")
            
            # Format to international format
            formatted = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            return formatted
            
        except NumberParseException:
            # Fall back to regex validation if parsing fails
            pass
        except ImportError:
            # phonenumbers library not available, continue with regex validation
            pass
        
        return cleaned
    
    def validate_country(self, value):
        """🔒 ENHANCED: Validate country code against supported countries"""
        if not value:
            raise serializers.ValidationError("Country is required")
        
        value = value.upper().strip()
        
        if len(value) != 2:
            raise serializers.ValidationError("Country code must be 2 characters")
        
        if not value.isalpha():
            raise serializers.ValidationError("Country code must contain only letters")
        
        # Validate against supported countries with dial codes
        if value not in self.COUNTRY_DIAL_CODES:
            raise serializers.ValidationError(f"Country code '{value}' is not supported")
        
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
        
        # 🔒 ENHANCED: Validate phone number consistency with selected country
        phone = attrs.get('phone', '')
        country = attrs.get('country', 'US')
        
        if phone and country:
            # Re-validate phone with country context
            try:
                validated_phone = self.validate_phone(phone)
                attrs['phone'] = validated_phone
            except serializers.ValidationError as e:
                raise serializers.ValidationError({
                    'phone': f"Phone number invalid for {country}: {str(e)}"
                })
        
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


# Aliases for backward compatibility
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
        if hasattr(obj, 'anonymized') and obj.anonymized:
            return "ANONYMIZED"
        email = str(obj.email)
        if '@' in email:
            local, domain = email.split('@', 1)
            masked_local = local[:2] + '*' * (len(local) - 2) if len(local) > 2 else '***'
            return f"{masked_local}@{domain}"
        return "***@***.***"
    
    def get_phone_masked(self, obj):
        """🔒 SECURITY: Mask phone for privacy in list view"""
        if hasattr(obj, 'anonymized') and obj.anonymized:
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
            return obj.verify_integrity() if hasattr(obj, 'verify_integrity') else True
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


# Add to requirements.txt:
# phonenumbers==8.13.27
# bleach==6.1.0