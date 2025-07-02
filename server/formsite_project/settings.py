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
    ALLOWED_HOSTS = ['localhost', '127.0.0.1']
else:
    allowed_hosts_env = os.environ.get('ALLOWED_HOSTS')
    if allowed_hosts_env:
        ALLOWED_HOSTS = [host.strip() for host in allowed_hosts_env.split(',')]
    
    # Render.com configuration
    if 'RENDER' in os.environ:
        render_host = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
        if render_host:
            ALLOWED_HOSTS.append(render_host)
    
    # Your backend URLs
    ALLOWED_HOSTS.extend([
        'full-request-backend.onrender.com',
        'formsite-backend.onrender.com',
    ])

# 🔒 ULTRA-SECURE FORM SYSTEM: Minimal apps for maximum security
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Security stack - Form-focused only
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'whitenoise.runserver_nostatic',
    'axes',                           # ✅ Brute force protection
    'csp',                           # ✅ Content Security Policy
    'django_cryptography',           # ✅ Field-level encryption
    'auditlog',                      # ✅ Audit logging
    
    # Local apps
    'submissions',
    'authentication',
    'security_monitoring',
]

# 🔒 SECURITY: Essential middleware for form security
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'axes.middleware.AxesMiddleware',
    'security_monitoring.middleware.SecurityMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'csp.middleware.CSPMiddleware',
]

ROOT_URLCONF = 'formsite_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

# 🔒 DATABASE: Secure database configuration
if 'DATABASE_URL' in os.environ:
    DATABASES = {
        'default': dj_database_url.config(
            default=os.environ.get('DATABASE_URL'),
            conn_max_age=600,
            conn_health_checks=True,
            ssl_require=not DEBUG,
        )
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# 🔒 SECURITY: Authentication with brute force protection
AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesStandaloneBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# 🔒 SECURITY: Ultra-strong password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 14}
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# 🔒 SECURITY: Axes configuration (brute force protection)
AXES_ENABLED = True
AXES_FAILURE_LIMIT = 3
AXES_COOLOFF_TIME = timedelta(hours=2)
AXES_RESET_ON_SUCCESS = True
AXES_ENABLE_ADMIN = False
AXES_LOCKOUT_PARAMETERS = ['username', 'ip_address']

# 🔒 SECURITY: Ultra-secure session configuration
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 900  # 15 minutes
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_NAME = 'formsite_sessionid'

# 🔒 SECURITY: Ultra-secure CSRF settings
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_NAME = 'formsite_csrftoken'
CSRF_TRUSTED_ORIGINS = [
    'https://formsite-client.onrender.com',
    'https://formsite-admin.onrender.com',
    'https://full-request-backend.onrender.com',
]

# 🔒 CACHE: Simple secure cache (no external dependencies)
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

# 🔒 SECURITY: Maximum production security headers
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_PRELOAD = True
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# 🔒 SECURITY: Ultra-strict Content Security Policy
CSP_DEFAULT_SRC = ("'none'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:")
CSP_FONT_SRC = ("'self'",)
CSP_CONNECT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)
CSP_BASE_URI = ("'self'",)
CSP_FORM_ACTION = ("'self'",)
CSP_FRAME_SRC = ("'none'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_REPORT_URI = '/api/security/csp-violation/'

# 🔒 SECURITY: REST Framework with maximum protection
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '20/hour',     # Ultra-strict for forms
        'user': '100/hour',    
        'submit': '2/minute',  # Max 2 form submissions per minute
        'login': '3/hour',     
    },
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
}

# 🔒 SECURITY: Ultra-secure JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=10),
    'REFRESH_TOKEN_LIFETIME': timedelta(hours=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFY_SIGNATURE': True,
    'VERIFY_EXP': True,
    'VERIFY_NBF': True,
    'REQUIRE_EXP': True,
    'REQUIRE_NBF': False,
}

# 🔒 SECURITY: Ultra-strict CORS for form submissions only
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False

if DEBUG:
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
else:
    CORS_ALLOWED_ORIGINS = [
        "https://formsite-client.onrender.com",
        "https://formsite-admin.onrender.com",
    ]

# 🔒 SECURITY: Minimal CORS headers for forms only
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

# 🔒 SECURITY: Form data limits (NO FILE UPLOADS)
DATA_UPLOAD_MAX_MEMORY_SIZE = 1048576  # 1MB max for form data
DATA_UPLOAD_MAX_NUMBER_FIELDS = 20     # Max 20 form fields
FILE_UPLOAD_MAX_MEMORY_SIZE = None      # Disable file uploads
FILE_UPLOAD_HANDLERS = []               # No file upload handlers

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# 🔒 DISABLE EMAIL: No email functionality needed
EMAIL_BACKEND = 'django.core.mail.backends.dummy.EmailBackend'

# 🔒 SECURITY: Data encryption settings
CRYPTOGRAPHY_KEY = os.environ.get('CRYPTOGRAPHY_KEY')
if not CRYPTOGRAPHY_KEY:
    if DEBUG:
        CRYPTOGRAPHY_KEY = secrets.token_urlsafe(32)
    else:
        raise ValueError("CRYPTOGRAPHY_KEY environment variable is required in production")

# 🔒 SECURITY: Security monitoring for forms
SECURITY_EMAIL_NOTIFICATIONS = False  # No email needed
SECURITY_LOG_FAILED_LOGINS = True
SECURITY_LOG_SUSPICIOUS_ACTIVITY = True
SECURITY_AUTO_BAN_THRESHOLD = 5
SECURITY_BAN_DURATION = 3600

# 🔒 SECURITY: Audit logging for all form data
AUDITLOG_INCLUDE_ALL_MODELS = True
AUDITLOG_EXCLUDE_TRACKING_MODELS = (
    'sessions.session',
    'admin.logentry',
    'contenttypes.contenttype',
    'auth.permission',
    'axes.accessattempt',
    'axes.accesslog',
)

# 🔒 SECURITY: Comprehensive logging for form security
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
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'security_file': {
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'security.log'),
            'formatter': 'security',
        } if not DEBUG else {
            'class': 'logging.StreamHandler',
            'formatter': 'security',
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
        'django.security': {
            'handlers': ['console', 'security_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'axes': {
            'handlers': ['console', 'security_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'submissions': {
            'handlers': ['console', 'security_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
}

# Create logs directory in production
if not DEBUG:
    os.makedirs(BASE_DIR / 'logs', exist_ok=True)

# Admin URL obfuscation
ADMIN_URL_PREFIX = os.environ.get('ADMIN_URL_PREFIX', 'admin')

# Development overrides
if DEBUG:
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_SSL_REDIRECT = False

# 🔒 FORM SECURITY: Additional form-specific settings
FORM_SUBMISSION_RATE_LIMIT = 2  # Max 2 submissions per minute per IP
FORM_DUPLICATE_CHECK_HOURS = 24  # Check for duplicates in last 24 hours
FORM_MAX_TEXT_LENGTH = 2000  # Max text field length
FORM_AUTO_CLEAN_HTML = True  # Auto-clean HTML input
FORM_BLOCK_SUSPICIOUS_PATTERNS = True  # Block suspicious input patterns

# Configuration summary for debugging
if DEBUG:
    print("🔒 ULTRA-SECURE FORM SYSTEM Configuration:")
    print(f"   DEBUG: {DEBUG}")
    print(f"   ALLOWED_HOSTS: {ALLOWED_HOSTS}")
    print(f"   DATABASE: {'PostgreSQL' if 'DATABASE_URL' in os.environ else 'SQLite'}")
    print(f"   SECRET_KEY: {'✅ Set' if SECRET_KEY else '❌ Missing'}")
    print(f"   CRYPTOGRAPHY_KEY: {'✅ Set' if CRYPTOGRAPHY_KEY else '❌ Missing'}")
    print(f"   SECURITY FEATURES:")
    print(f"     - Field-level encryption: ✅")
    print(f"     - Brute force protection: ✅")
    print(f"     - Content Security Policy: ✅")
    print(f"     - Audit logging: ✅")
    print(f"     - Form rate limiting: ✅")
    print(f"     - Input sanitization: ✅")
    print(f"     - NO file uploads: ✅")
    print(f"     - NO email system: ✅")
    print(f"     - Ultra-secure sessions: ✅")