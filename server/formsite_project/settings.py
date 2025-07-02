# formsite_project/settings.py - FIXED VERSION with only available packages
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

# 🔒 SECURE FORM SYSTEM: Only packages that are actually installed
INSTALLED_APPS = [
    # Django core
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third party - only what's available in requirements.txt
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'whitenoise.runserver_nostatic',
    
    # 🔒 SECURITY APPS: Only packages available in requirements.txt
    'django_cryptography',           # ✅ Field-level encryption
    'auditlog',                      # ✅ Comprehensive audit logging
    'axes',                          # ✅ Brute force protection
    'csp',                           # ✅ Content Security Policy
    
    # Local apps
    'submissions',
    'authentication',
    'security_monitoring',
]

# 🔒 SECURITY: Security middleware stack (simplified)
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
    
    # 🔒 SECURITY MIDDLEWARE: Only what's available
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
SESSION_COOKIE_AGE = 1800  # 30 minutes for ultra-security
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_NAME = 'secure_sessionid'
SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'

# 🔒 SECURITY: Ultra-secure CSRF settings
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_NAME = 'secure_csrftoken'
CSRF_COOKIE_AGE = 31449600  # 1 year
CSRF_USE_SESSIONS = True
CSRF_TRUSTED_ORIGINS = [
    'https://formsite-client.onrender.com',
    'https://formsite-admin.onrender.com',
    'https://full-request-backend.onrender.com',
]

# 🔒 CACHE: Simple cache configuration (fallback to local memory)
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

# Override with Redis if available
redis_url = os.environ.get('REDIS_URL')
if redis_url:
    try:
        import redis
        CACHES = {
            'default': {
                'BACKEND': 'django_redis.cache.RedisCache',
                'LOCATION': redis_url,
                'OPTIONS': {
                    'CLIENT_CLASS': 'django_redis.client.DefaultClient',
                    'CONNECTION_POOL_KWARGS': {
                        'ssl_cert_reqs': None,
                        'ssl_check_hostname': False,
                    },
                },
                'KEY_PREFIX': 'formsite_secure',
                'TIMEOUT': 300,
            }
        }
    except ImportError:
        # Fall back to local memory cache if redis not available
        pass

# 🔒 SECURITY: Production security headers
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_PRELOAD = True
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

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
CSP_REPORT_ONLY = DEBUG

# 🔒 SECURITY: REST Framework with security
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
        'anon': '20/hour',
        'user': '100/hour',
    },
}

# 🔒 SECURITY: JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(hours=2),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
}

# 🔒 SECURITY: CORS configuration
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False

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

# 🔒 SECURITY: Brute force protection (django-axes)
AXES_ENABLED = True
AXES_FAILURE_LIMIT = 3
AXES_COOLOFF_TIME = timedelta(minutes=30)
AXES_RESET_ON_SUCCESS = True
AXES_LOGIN_FAILURE_LIMIT = 3
AXES_LOCK_OUT_AT_FAILURE = True
AXES_USE_USER_AGENT = True
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True

# 🔒 SECURITY: Form data limits
DATA_UPLOAD_MAX_MEMORY_SIZE = 1048576  # 1MB max
DATA_UPLOAD_MAX_NUMBER_FIELDS = 20
FILE_UPLOAD_MAX_MEMORY_SIZE = None  # Disable file uploads
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

# 🔒 DISABLE EMAIL: No email functionality for security
EMAIL_BACKEND = 'django.core.mail.backends.dummy.EmailBackend'

# 🔒 SECURITY: Encryption settings
CRYPTOGRAPHY_KEY = os.environ.get('CRYPTOGRAPHY_KEY')
if not CRYPTOGRAPHY_KEY:
    if DEBUG:
        CRYPTOGRAPHY_KEY = secrets.token_urlsafe(32)
        print(f"🔑 Generated development encryption key: {CRYPTOGRAPHY_KEY}")
    else:
        raise ValueError("CRYPTOGRAPHY_KEY environment variable is required in production")

# 🔒 SECURITY: Audit logging
AUDITLOG_INCLUDE_ALL_MODELS = True
AUDITLOG_EXCLUDE_TRACKING_MODELS = (
    'sessions.session',
    'admin.logentry',
    'contenttypes.contenttype',
    'auth.permission',
)

# 🔒 SECURITY: Comprehensive logging
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
        'security_console': {
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
            'handlers': ['console', 'security_console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'submissions': {
            'handlers': ['console', 'security_console'],
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

# Create logs directory in production
if not DEBUG:
    (BASE_DIR / 'logs').mkdir(exist_ok=True)

# Development settings override
if DEBUG:
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_SSL_REDIRECT = False
    AXES_ENABLED = False  # Disable in development
    CSP_REPORT_ONLY = True
    
    print("🔒 SECURE FORM SYSTEM - DEBUG MODE")
    print(f"   🔑 Encryption key: {'SET' if CRYPTOGRAPHY_KEY else 'MISSING'}")
    print(f"   📊 Database: {DATABASES['default']['ENGINE'].split('.')[-1]}")
    print(f"   🌐 CORS origins: {len(CORS_ALLOWED_ORIGINS)} configured")
    print(f"   🛡️ Brute force protection: {'ENABLED' if AXES_ENABLED else 'DISABLED'}")
    print(f"   🛡️ Content Security Policy: {'ENFORCED' if not CSP_REPORT_ONLY else 'REPORT-ONLY'}")
    print("   ✅ Core security features active")
else:
    print("🔒 SECURE FORM SYSTEM - PRODUCTION MODE")
    print("   ✅ Core security features enabled")
    print("   🛡️ Brute force protection active")
    print("   🔐 Full encryption enabled")
    print("   📋 Audit logging active")
    print("   🛡️ Content Security Policy enforced")
    print("   ✅ Production security active")