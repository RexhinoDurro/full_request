# formsite_project/settings.py - SUBDOMAIN ADMIN VERSION
import os
import dj_database_url
from pathlib import Path
from datetime import timedelta
import secrets

BASE_DIR = Path(__file__).resolve().parent.parent

# 🔒 SECURITY: Environment-based secret key
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    if os.environ.get('DEBUG', 'False').lower() == 'true':
        SECRET_KEY = 'dev-key-change-in-production'
    else:
        raise ValueError("SECRET_KEY environment variable is required in production")

DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# 🔒 SECURITY: Subdomain-aware allowed hosts
ALLOWED_HOSTS = []
if DEBUG:
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']
else:
    allowed_hosts_env = os.environ.get('ALLOWED_HOSTS')
    if allowed_hosts_env:
        ALLOWED_HOSTS = [host.strip() for host in allowed_hosts_env.split(',')]
    else:
        # Default production subdomains
        ALLOWED_HOSTS = [
            'cryptofacilities.eu',
            'www.cryptofacilities.eu',
            'admin-secure.cryptofacilities.eu',  # 🔒 Admin subdomain
        ]

# 🔒 SECURITY: Ultra-secure application setup
INSTALLED_APPS = [
    # Django core
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third party
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'whitenoise.runserver_nostatic',
    
    # Security apps
    'django_cryptography',
    'auditlog',
    'axes',
    'csp',
    
    # Local apps
    'submissions',
    'authentication',
    'security_monitoring',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'axes.middleware.AxesMiddleware',
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

# 🔒 VPS DATABASE CONFIGURATION
if 'DATABASE_URL' in os.environ:
    DATABASES = {
        'default': dj_database_url.config(
            default=os.environ.get('DATABASE_URL'),
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
    if not DEBUG:
        DATABASES['default']['OPTIONS'] = {
            'sslmode': 'prefer',
        }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12}
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# 🔒 SECURITY: Ultra-secure session configuration
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 1800
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_NAME = 'secure_sessionid'

# 🔒 SECURITY: Ultra-secure CSRF settings with subdomain support
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'  # Allow cross-subdomain for admin
CSRF_COOKIE_NAME = 'secure_csrftoken'
CSRF_COOKIE_AGE = 31449600
CSRF_USE_SESSIONS = True

# 🔒 SUBDOMAIN: CSRF trusted origins for subdomain admin
CSRF_TRUSTED_ORIGINS = []
csrf_origins_env = os.environ.get('CSRF_TRUSTED_ORIGINS')
if csrf_origins_env:
    CSRF_TRUSTED_ORIGINS = [origin.strip() for origin in csrf_origins_env.split(',')]
else:
    # Default trusted origins for subdomain setup
    if not DEBUG:
        CSRF_TRUSTED_ORIGINS = [
            'https://cryptofacilities.eu',
            'https://www.cryptofacilities.eu',
            'https://admin-secure.cryptofacilities.eu',  # 🔒 Admin subdomain
        ]

# Cache configuration (Redis removed)
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

# 🔒 SECURITY: Production security headers
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_PRELOAD = True
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Content Security Policy with subdomain support
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'",)
CSP_CONNECT_SRC = (
    "'self'", 
    "https://cryptofacilities.eu",  # Allow admin to connect to main API
    "https://admin-secure.cryptofacilities.eu"  # Admin subdomain
)
CSP_OBJECT_SRC = ("'none'",)
CSP_BASE_URI = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)
CSP_FORM_ACTION = ("'self'",)
CSP_INCLUDE_NONCE_IN = ['script-src', 'style-src']
CSP_REPORT_ONLY = DEBUG

# REST Framework configuration
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
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '50/hour',
        'user': '100/hour',
    },
}

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(hours=2),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
}

# 🔒 SUBDOMAIN: CORS configuration for subdomain admin
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False

# 🔒 SUBDOMAIN: Specific CORS origins for subdomain setup
CORS_ALLOWED_ORIGINS = []
cors_origins_env = os.environ.get('CORS_ALLOWED_ORIGINS')
if cors_origins_env:
    CORS_ALLOWED_ORIGINS = [origin.strip() for origin in cors_origins_env.split(',')]
else:
    # Default CORS origins for subdomain setup
    if not DEBUG:
        CORS_ALLOWED_ORIGINS = [
            "https://cryptofacilities.eu",
            "https://www.cryptofacilities.eu", 
            "https://admin-secure.cryptofacilities.eu",  # 🔒 Admin subdomain
        ]

if DEBUG:
    CORS_ALLOWED_ORIGINS.extend([
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ])

# 🔒 SUBDOMAIN: Enhanced CORS headers for admin subdomain
CORS_ALLOWED_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'x-admin-domain',  # Custom header for admin subdomain identification
]

CORS_ALLOW_METHODS = [
    'GET',
    'POST',
    'PUT',
    'DELETE',
    'OPTIONS',
]

# 🔒 SUBDOMAIN: Additional security for admin subdomain
CORS_EXPOSE_HEADERS = [
    'x-admin-authenticated',
    'x-security-token',
]

# Brute force protection
AXES_ENABLED = True
AXES_FAILURE_LIMIT = 3
AXES_COOLOFF_TIME = timedelta(minutes=30)
AXES_RESET_ON_SUCCESS = True
AXES_LOGIN_FAILURE_LIMIT = 3
AXES_LOCK_OUT_AT_FAILURE = True
AXES_USE_USER_AGENT = True
AXES_LOCKOUT_PARAMETERS = ['username', 'ip_address']

# Form security
DATA_UPLOAD_MAX_MEMORY_SIZE = 1048576  # 1MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = 20
FILE_UPLOAD_MAX_MEMORY_SIZE = None
FILE_UPLOAD_HANDLERS = []

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

# Email configuration (disabled by default for security)
EMAIL_BACKEND = 'django.core.mail.backends.dummy.EmailBackend'

# Encryption settings
CRYPTOGRAPHY_KEY = os.environ.get('CRYPTOGRAPHY_KEY')
if not CRYPTOGRAPHY_KEY:
    if DEBUG:
        CRYPTOGRAPHY_KEY = secrets.token_urlsafe(32)
        print(f"🔑 Generated development encryption key: {CRYPTOGRAPHY_KEY}")
    else:
        raise ValueError("CRYPTOGRAPHY_KEY environment variable is required in production")

# Audit logging
AUDITLOG_INCLUDE_ALL_MODELS = True
AUDITLOG_EXCLUDE_TRACKING_MODELS = (
    'sessions.session',
    'admin.logentry',
    'contenttypes.contenttype',
    'auth.permission',
)

# 🔒 SUBDOMAIN: Custom security settings
ADMIN_SUBDOMAIN_DOMAINS = [
    'admin-secure.cryptofacilities.eu',
    'admin.cryptofacilities.eu',  # Alternative admin subdomain
]

# 🔒 SUBDOMAIN: Additional security middleware configuration
SECURE_SUBDOMAIN_ADMIN = not DEBUG  # Enable subdomain security in production
ADMIN_IP_WHITELIST = os.environ.get('ADMIN_IP_WHITELIST', '').split(',') if os.environ.get('ADMIN_IP_WHITELIST') else []

# Logging configuration
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
        'admin_subdomain': {
            'format': 'ADMIN_SUBDOMAIN {levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'security_console': {
            'class': 'logging.StreamHandler',
            'formatter': 'security',
        },
        'admin_console': {
            'class': 'logging.StreamHandler',
            'formatter': 'admin_subdomain',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'security_monitoring': {
            'handlers': ['console', 'security_console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'submissions': {
            'handlers': ['console', 'security_console'],
            'level': 'INFO',
            'propagate': False,
        },
        'admin_subdomain': {
            'handlers': ['admin_console', 'security_console'],
            'level': 'INFO',
            'propagate': False,
        },
        'auditlog': {
            'handlers': ['security_console'],
            'level': 'INFO',
            'propagate': False,
        },
        'axes': {
            'handlers': ['security_console'],
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
(BASE_DIR / 'logs').mkdir(exist_ok=True)

# Development overrides
if DEBUG:
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_SSL_REDIRECT = False
    AXES_ENABLED = False
    CSP_REPORT_ONLY = True
    SECURE_SUBDOMAIN_ADMIN = False
    
    print("🔒 SUBDOMAIN DEPLOYMENT - DEBUG MODE")
    print(f"   🔑 Encryption key: {'SET' if CRYPTOGRAPHY_KEY else 'MISSING'}")
    print(f"   📊 Database: {DATABASES['default']['ENGINE'].split('.')[-1]}")
    print(f"   🌐 CORS origins: {len(CORS_ALLOWED_ORIGINS)} configured")
    print(f"   🔗 Admin subdomains: {', '.join(ADMIN_SUBDOMAIN_DOMAINS)}")
    print(f"   🛡️ Brute force protection: {'ENABLED' if AXES_ENABLED else 'DISABLED'}")
    print("   ✅ Subdomain admin deployment ready")
else:
    print("🔒 SUBDOMAIN DEPLOYMENT - PRODUCTION MODE")
    print("   ✅ All security features enabled")
    print("   🔗 Admin subdomain security active")
    print("   🛡️ Production-ready subdomain configuration")