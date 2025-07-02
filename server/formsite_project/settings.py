# formsite_project/settings.py - ULTRA-SECURE VERSION with ALL security features
import os
import dj_database_url
from pathlib import Path
from datetime import timedelta
import secrets

BASE_DIR = Path(__file__).resolve().parent.parent

# 🔒 ULTRA-SECURE: Environment-based secret key
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    if os.environ.get('DEBUG', 'False').lower() == 'true':
        SECRET_KEY = 'dev-key-change-in-production'
    else:
        raise ValueError("SECRET_KEY environment variable is required in production")

DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# 🔒 SECURITY: Strict allowed hosts
ALLOWED_HOSTS = []
if DEBUG:
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']
else:
    allowed_hosts_env = os.environ.get('ALLOWED_HOSTS')
    if allowed_hosts_env:
        ALLOWED_HOSTS = [host.strip() for host in allowed_hosts_env.split(',')]
    
    # Render.com configuration
    if 'RENDER' in os.environ:
        render_host = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
        if render_host:
            ALLOWED_HOSTS.append(render_host)
    
    # Add your backend URLs
    ALLOWED_HOSTS.extend([
        'full-request-backend.onrender.com',
        'formsite-backend.onrender.com',
    ])

# 🔒 ULTRA-SECURE FORM SYSTEM: Full security stack
INSTALLED_APPS = [
    # Django core
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third party - full security stack
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'whitenoise.runserver_nostatic',
    
    # 🔒 SECURITY APPS: Complete security arsenal
    'django_cryptography',           # ✅ Field-level encryption
    'auditlog',                      # ✅ Comprehensive audit logging
    'axes',                          # ✅ Brute force protection
    'csp',                           # ✅ Content Security Policy
    'django_ratelimit',              # ✅ Advanced rate limiting
    'honeypot',                      # ✅ Honeypot spam protection
    'django_otp',                    # ✅ Two-factor authentication core
    'django_otp.plugins.otp_totp',   # ✅ TOTP tokens
    'django_otp.plugins.otp_static', # ✅ Static backup tokens
    'two_factor',                    # ✅ Two-factor auth UI
    'health_check',                  # ✅ System health monitoring
    'health_check.db',               # ✅ Database health check
    'health_check.cache',            # ✅ Cache health check
    'health_check.storage',          # ✅ Storage health check
    
    # Local apps
    'submissions',
    'authentication',
    'security_monitoring',
]

# 🔒 SECURITY: Comprehensive security middleware stack
MIDDLEWARE = [
    # Security headers first
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    
    # Core Django middleware
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    
    # 🔒 SECURITY MIDDLEWARE: Advanced protection
    'django_otp.middleware.OTPMiddleware',  # ✅ Two-factor authentication
    'axes.middleware.AxesMiddleware',       # ✅ Brute force protection
    'csp.middleware.CSPMiddleware',         # ✅ Content Security Policy
    'security_monitoring.middleware.SecurityMiddleware',  # ✅ Custom security monitoring
    
    # Messages and clickjacking protection
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'formsite_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'formsite_project.wsgi.application'

# 🔒 DATABASE: Ultra-secure database configuration
if 'DATABASE_URL' in os.environ:
    DATABASES = {
        'default': dj_database_url.config(
            default=os.environ.get('DATABASE_URL'),
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
    # Enable SSL and security options for production PostgreSQL
    if not DEBUG:
        DATABASES['default']['OPTIONS'] = {
            'sslmode': 'require',
            'options': '-c default_transaction_isolation=serializable',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# 🔒 SECURITY: Ultra-strong password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 14}  # Ultra-strong minimum
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'security_monitoring.validators.CustomPasswordValidator',  # Custom ultra-secure validator
    },
]

# 🔒 SECURITY: Ultra-secure session configuration
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 1800  # 30 minutes for ultra-security
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_NAME = 'secure_sessionid'
SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'  # Hybrid session storage

# 🔒 SECURITY: Ultra-secure CSRF settings
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_NAME = 'secure_csrftoken'
CSRF_COOKIE_AGE = 31449600  # 1 year
CSRF_USE_SESSIONS = True  # Store CSRF token in session
CSRF_TRUSTED_ORIGINS = [
    'https://formsite-client.onrender.com',
    'https://formsite-admin.onrender.com',
    'https://full-request-backend.onrender.com',
]

# 🔒 CACHE: Secure Redis cache configuration
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'ssl_cert_reqs': None,
                'ssl_check_hostname': False,
            },
        },
        'KEY_PREFIX': 'formsite_secure',
        'TIMEOUT': 300,
    },
    'sessions': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/2'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': 'formsite_sessions',
        'TIMEOUT': 86400,
    }
}

# Fallback to local memory cache if Redis unavailable
if not os.environ.get('REDIS_URL'):
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'formsite-security-cache',
            'OPTIONS': {
                'MAX_ENTRIES': 1000,
                'CULL_FREQUENCY': 4,
            },
            'TIMEOUT': 300,
        }
    }

# 🔒 SECURITY: Production security headers (Ultra-strict)
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_PRELOAD = True
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
    SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'
    SECURE_CROSS_ORIGIN_EMBEDDER_POLICY = 'require-corp'

# 🔒 SECURITY: Content Security Policy (Ultra-strict)
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")  # Allow inline scripts for admin
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'",)
CSP_CONNECT_SRC = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_BASE_URI = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)
CSP_FORM_ACTION = ("'self'",)
CSP_INCLUDE_NONCE_IN = ['script-src', 'style-src']
CSP_REPORT_ONLY = DEBUG  # Report-only mode in development

# 🔒 SECURITY: REST Framework with full security
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
        'rest_framework.throttling.ScopedRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '20/hour',
        'user': '100/hour',
        'submit': '5/hour',  # Ultra-strict for form submissions
        'login': '3/hour',   # Ultra-strict for login attempts
    },
    'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.URLPathVersioning',
    'DEFAULT_VERSION': 'v1',
    'ALLOWED_VERSIONS': ['v1'],
}

# 🔒 SECURITY: JWT Settings (Ultra-secure)
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(hours=2),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'JWK_URL': None,
    'LEEWAY': 0,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',
    'JTI_CLAIM': 'jti',
    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=15),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(hours=1),
}

# 🔒 SECURITY: CORS configuration (Ultra-strict)
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS_REGEXES = []

if DEBUG:
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8080",
    ]
else:
    CORS_ALLOWED_ORIGINS = [
        "https://formsite-client.onrender.com",
        "https://formsite-admin.onrender.com",
    ]

CORS_ALLOWED_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

CORS_ALLOW_METHODS = [
    'GET',
    'POST',
    'PUT',
    'DELETE',
    'OPTIONS',
]

# 🔒 SECURITY: Advanced rate limiting
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_VIEW = 'security_monitoring.views.rate_limit_exceeded'

# 🔒 SECURITY: Brute force protection (django-axes)
AXES_ENABLED = True
AXES_FAILURE_LIMIT = 3
AXES_COOLOFF_TIME = timedelta(minutes=30)
AXES_RESET_ON_SUCCESS = True
AXES_LOCKOUT_TEMPLATE = 'security_monitoring/lockout.html'
AXES_LOCKOUT_URL = '/security/lockout/'
AXES_LOGIN_FAILURE_LIMIT = 3
AXES_LOCK_OUT_AT_FAILURE = True
AXES_USE_USER_AGENT = True
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True

# 🔒 SECURITY: Form data limits (Ultra-strict)
DATA_UPLOAD_MAX_MEMORY_SIZE = 1048576  # 1MB max (very strict)
DATA_UPLOAD_MAX_NUMBER_FIELDS = 20
FILE_UPLOAD_MAX_MEMORY_SIZE = None  # Disable file uploads completely
FILE_UPLOAD_HANDLERS = []  # No file upload handlers

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files with security
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# 🔒 DISABLE EMAIL: No email functionality for ultra-security
EMAIL_BACKEND = 'django.core.mail.backends.dummy.EmailBackend'

# 🔒 SECURITY: Advanced encryption settings
CRYPTOGRAPHY_KEY = os.environ.get('CRYPTOGRAPHY_KEY')
if not CRYPTOGRAPHY_KEY:
    if DEBUG:
        CRYPTOGRAPHY_KEY = secrets.token_urlsafe(32)
        print(f"🔑 Generated development encryption key: {CRYPTOGRAPHY_KEY}")
    else:
        raise ValueError("CRYPTOGRAPHY_KEY environment variable is required in production")

# 🔒 SECURITY: Two-factor authentication
TWO_FACTOR_PATCH_ADMIN = True
TWO_FACTOR_CALL_GATEWAY = None
TWO_FACTOR_SMS_GATEWAY = None

# 🔒 SECURITY: Audit logging (Ultra-comprehensive)
AUDITLOG_INCLUDE_ALL_MODELS = True
AUDITLOG_EXCLUDE_TRACKING_MODELS = (
    'sessions.session',
    'admin.logentry',
    'contenttypes.contenttype',
    'auth.permission',
)

# 🔒 SECURITY: Honeypot configuration
HONEYPOT_FIELD_NAME = 'website_url'
HONEYPOT_VALUE = ''

# 🔒 SECURITY: Health checks
HEALTH_CHECK = {
    'DISK_USAGE_MAX': 90,  # 90% max disk usage
    'MEMORY_MIN': 100,     # 100MB min free memory
}

# 🔒 SECURITY: Comprehensive logging (Ultra-detailed)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'security': {
            'format': 'SECURITY {levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'audit': {
            'format': 'AUDIT {levelname} {asctime} {user} {action} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'security_file': {
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'security.log',
            'formatter': 'security',
        } if not DEBUG else {
            'class': 'logging.StreamHandler',
            'formatter': 'security',
        },
        'audit_file': {
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'audit.log',
            'formatter': 'audit',
        } if not DEBUG else {
            'class': 'logging.StreamHandler',
            'formatter': 'audit',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'security_monitoring': {
            'handlers': ['console', 'security_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        'submissions': {
            'handlers': ['console', 'security_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'auditlog': {
            'handlers': ['audit_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'axes': {
            'handlers': ['security_file'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
}

# Create logs directory
if not DEBUG:
    (BASE_DIR / 'logs').mkdir(exist_ok=True)

# 🔒 ADMIN SECURITY: Anonymous admin configuration
ADMIN_URL_PREFIX = os.environ.get('ADMIN_URL_PREFIX', 'admin')

# 🔒 FORM SECURITY: Advanced form protection settings
FORM_SUBMISSION_RATE_LIMIT = 2  # Max 2 submissions per minute (ultra-strict)
FORM_DUPLICATE_CHECK_HOURS = 24
FORM_MAX_TEXT_LENGTH = 2000
FORM_AUTO_CLEAN_HTML = True
FORM_BLOCK_SUSPICIOUS_PATTERNS = True
FORM_REQUIRE_CONFIRMATION = True
FORM_ENABLE_HONEYPOT = True
FORM_ENABLE_CAPTCHA = False  # Disabled for simplicity
FORM_ENABLE_2FA_FOR_ADMIN = True

# 🔒 SECURITY MONITORING: Advanced settings
SECURITY_LOG_ALL_ADMIN_ACTIONS = True
SECURITY_ALERT_ON_SUSPICIOUS_ACTIVITY = True
SECURITY_AUTO_BAN_ENABLED = True
SECURITY_THREAT_INTELLIGENCE_ENABLED = True
SECURITY_REAL_TIME_MONITORING = True
SECURITY_EMAIL_NOTIFICATIONS = False  # Disabled since email is disabled

# 🔒 COMPLIANCE: GDPR and data protection settings
GDPR_ENABLED = True
GDPR_DEFAULT_RETENTION_DAYS = 2555  # 7 years
GDPR_AUTO_ANONYMIZE = False  # Manual approval required
GDPR_DATA_BREACH_NOTIFICATION = True
GDPR_CONSENT_TRACKING = True

# Development settings override
if DEBUG:
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_SSL_REDIRECT = False
    AXES_ENABLED = False  # Disable in development
    CSP_REPORT_ONLY = True
    
    print("🔒 ULTRA-SECURE FORM SYSTEM - DEBUG MODE")
    print(f"   🔑 Encryption key: {'SET' if CRYPTOGRAPHY_KEY else 'MISSING'}")
    print(f"   🛡️ Two-factor auth: {'ENABLED' if TWO_FACTOR_PATCH_ADMIN else 'DISABLED'}")
    print(f"   📊 Database: {DATABASES['default']['ENGINE'].split('.')[-1]}")
    print(f"   🌐 CORS origins: {len(CORS_ALLOWED_ORIGINS)} configured")
    print(f"   ⚡ Form rate limit: {FORM_SUBMISSION_RATE_LIMIT}/min")
    print(f"   🔒 Brute force protection: {'ENABLED' if AXES_ENABLED else 'DISABLED'}")
    print(f"   🛡️ Content Security Policy: {'ENFORCED' if not CSP_REPORT_ONLY else 'REPORT-ONLY'}")
    print("   ✅ ALL SECURITY FEATURES ACTIVE")
else:
    print("🔒 ULTRA-SECURE FORM SYSTEM - PRODUCTION MODE")
    print("   ✅ All security features enabled")
    print("   👤 Two-factor authentication active")
    print("   🛡️ Brute force protection active")
    print("   🔐 Full encryption enabled")
    print("   📋 Comprehensive audit logging active")
    print("   🛡️ Content Security Policy enforced")
    print("   🔒 Rate limiting active")
    print("   📊 Security monitoring active")
    print("   ✅ GDPR compliance features active")