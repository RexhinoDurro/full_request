import os
import dj_database_url
from pathlib import Path
from datetime import timedelta
import secrets

BASE_DIR = Path(__file__).resolve().parent.parent

# Security-first configuration
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    if os.environ.get('DEBUG', 'False').lower() == 'true':
        SECRET_KEY = 'dev-key-change-in-production'
    else:
        raise ValueError("SECRET_KEY environment variable is required in production")

DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# Strict allowed hosts
ALLOWED_HOSTS = []
if DEBUG:
    ALLOWED_HOSTS = ['localhost', '127.0.0.1']
else:
    allowed_hosts_env = os.environ.get('ALLOWED_HOSTS')
    if allowed_hosts_env:
        ALLOWED_HOSTS = [host.strip() for host in allowed_hosts_env.split(',')]
    
    # Render.com specific configuration
    if 'RENDER' in os.environ:
        render_host = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
        if render_host:
            ALLOWED_HOSTS.append(render_host)
    
    # Add your specific backend URL
    ALLOWED_HOSTS.extend([
        'full-request-backend.onrender.com',
        'formsite-backend.onrender.com',  # backup name
    ])

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third party apps
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'whitenoise.runserver_nostatic',
    'axes',
    'django_cryptography',
    
    # Local apps
    'submissions',
    'authentication',
    'security_monitoring',
]

# ✅ FIXED: Simplified middleware stack for API-first application
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # ✅ REMOVED: CSRF middleware for API endpoints
    # 'django.middleware.csrf.CsrfViewMiddleware',  # Commented out
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'axes.middleware.AxesMiddleware',
    'security_monitoring.middleware.SecurityMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
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

# Database configuration
if 'DATABASE_URL' in os.environ:
    DATABASES = {
        'default': dj_database_url.config(
            default=os.environ.get('DATABASE_URL'),
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesStandaloneBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# Enhanced password validation
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

# Axes configuration (brute force protection)
AXES_ENABLED = True
AXES_FAILURE_LIMIT = 3
AXES_COOLOFF_TIME = timedelta(hours=1)
AXES_RESET_ON_SUCCESS = True
AXES_ENABLE_ADMIN = False
AXES_LOCKOUT_PARAMETERS = ['username', 'ip_address']

# Session Security (Enhanced) - ✅ RELAXED for API usage
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'  # ✅ CHANGED: Lax instead of Strict for better API compatibility
SESSION_COOKIE_AGE = 1800  # 30 minutes
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_NAME = 'formsite_sessionid'

# ✅ FIXED: CSRF settings - disabled for API-first approach
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_NAME = 'formsite_csrftoken'

# ✅ UPDATED: Trusted origins for your actual deployment URLs
CSRF_TRUSTED_ORIGINS = [
    'https://formsite-client.onrender.com',
    'https://formsite-admin.onrender.com', 
    'https://full-request-backend.onrender.com',
]

# ✅ NEW: Disable CSRF for API endpoints globally
CSRF_EXEMPT_URLS = [
    r'^api/',  # All API endpoints are CSRF exempt
]

# Cache configuration
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'django_cache_table',
    }
}

# Security Headers (Production)
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_PRELOAD = True
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Django REST Framework (Secure)
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',  # ✅ CHANGED: Default to AllowAny for public APIs
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '60/hour',
        'user': '500/hour',
        'submit': '3/minute',
        'login': '5/hour',
    },
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
}

# JWT Settings (Secure)
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(hours=2),
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

# ✅ FIXED: CORS settings (Proper configuration for your deployment)
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False

if DEBUG:
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",  # Vite dev server
        "http://127.0.0.1:5173",
    ]
else:
    # ✅ PRODUCTION: Your actual frontend URLs
    CORS_ALLOWED_ORIGINS = [
        "https://formsite-client.onrender.com",
        "https://formsite-admin.onrender.com",
    ]
    
    # Also allow from environment variable if set
    frontend_url = os.environ.get('FRONTEND_URL')
    if frontend_url:
        CORS_ALLOWED_ORIGINS.append(frontend_url)
    
    # Parse from comma-separated environment variable
    cors_origins_env = os.environ.get('CORS_ALLOWED_ORIGINS')
    if cors_origins_env:
        additional_origins = [origin.strip() for origin in cors_origins_env.split(',') if origin.strip()]
        CORS_ALLOWED_ORIGINS.extend(additional_origins)

# CORS headers
CORS_ALLOWED_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# File upload security
FILE_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
FILE_UPLOAD_PERMISSIONS = 0o644
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o755

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

# Email settings
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
if not DEBUG and os.environ.get('EMAIL_HOST'):
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = os.environ.get('EMAIL_HOST')
    EMAIL_PORT = int(os.environ.get('EMAIL_PORT', '587'))
    EMAIL_USE_TLS = True
    EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
    EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')
    DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'security@formsite.com')

# Data encryption settings
CRYPTOGRAPHY_KEY = os.environ.get('CRYPTOGRAPHY_KEY')
if not CRYPTOGRAPHY_KEY:
    if DEBUG:
        CRYPTOGRAPHY_KEY = secrets.token_urlsafe(32)
    else:
        raise ValueError("CRYPTOGRAPHY_KEY environment variable is required in production")

# Security monitoring
SECURITY_EMAIL_NOTIFICATIONS = not DEBUG
SECURITY_LOG_FAILED_LOGINS = True
SECURITY_LOG_SUSPICIOUS_ACTIVITY = True
SECURITY_IP_WHITELIST = os.environ.get('ADMIN_IP_WHITELIST', '').split(',') if os.environ.get('ADMIN_IP_WHITELIST') else []

# ✅ SIMPLIFIED: Logging configuration with better error handling
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
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'security_monitoring': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
}

# Print configuration summary (only in DEBUG)
if DEBUG:
    print("🔧 Django Configuration Summary:")
    print(f"   DEBUG: {DEBUG}")
    print(f"   ALLOWED_HOSTS: {ALLOWED_HOSTS}")
    print(f"   CORS_ALLOWED_ORIGINS: {CORS_ALLOWED_ORIGINS}")
    print(f"   DATABASE: {'PostgreSQL' if 'DATABASE_URL' in os.environ else 'SQLite'}")
    print(f"   SECRET_KEY: {'✅ Set' if SECRET_KEY else '❌ Missing'}")
    print(f"   CRYPTOGRAPHY_KEY: {'✅ Set' if CRYPTOGRAPHY_KEY else '❌ Missing'}")
    print(f"   CSRF_MIDDLEWARE: {'❌ Disabled for APIs' if 'django.middleware.csrf.CsrfViewMiddleware' not in MIDDLEWARE else '✅ Enabled'}")