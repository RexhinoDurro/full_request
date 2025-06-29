import os
import dj_database_url
from pathlib import Path
from datetime import timedelta
import secrets

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-development-key-change-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'

# Allowed hosts
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

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
    'django_ratelimit',
    'axes',  # For brute force protection
    'csp',   # Content Security Policy
    'django_cryptography',  # Field encryption
    'auditlog',  # Audit logging
    
    # Local apps
    'submissions',
    'authentication',
    'security_monitoring',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'axes.middleware.AxesMiddleware',  # Brute force protection
    'security_monitoring.middleware.SecurityMiddleware',  # Custom security middleware
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'csp.middleware.CSPMiddleware',  # Content Security Policy
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
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite3')

if DATABASE_URL.startswith('sqlite'):
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
else:
    DATABASES = {
        'default': dj_database_url.config(
            default=DATABASE_URL,
            conn_max_age=600,
            conn_health_checks=True,
        )
    }

# Authentication backends (FIXED: Added Axes backend)
AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesStandaloneBackend',  # AxesStandaloneBackend should be first
    'django.contrib.auth.backends.ModelBackend',
]

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 8}  # Reasonable for development
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# FIXED: Updated Axes settings (removed deprecated settings)
AXES_ENABLED = True
AXES_FAILURE_LIMIT = 3  # Lock after 3 failed attempts
AXES_COOLOFF_TIME = timedelta(minutes=30)  # 30 minute lockout
AXES_RESET_ON_SUCCESS = True
AXES_ENABLE_ADMIN = False
AXES_LOCKOUT_PARAMETERS = ['username', 'ip_address']  # New setting instead of deprecated ones

# Session Security
SESSION_COOKIE_SECURE = not DEBUG  # False for development, True for production
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 3600  # 1 hour sessions
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True

# CSRF Protection
CSRF_COOKIE_SECURE = not DEBUG  # False for development, True for production
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Enhanced Security Headers (disabled for development)
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_PRELOAD = True
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# FIXED: Updated Content Security Policy to new format
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src': ("'self'", "'unsafe-inline'"),
        'style-src': ("'self'", "'unsafe-inline'"),
        'img-src': ("'self'", "data:", "https:"),
        'font-src': ("'self'",),
        'connect-src': ("'self'",),
        'frame-ancestors': ("'none'",),
        'base-uri': ("'self'",),
        'form-action': ("'self'",),
    }
}

# Django REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'submit': '5/minute',
        'login': '10/hour',
    },
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
}

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),
    'REFRESH_TOKEN_LIFETIME': timedelta(hours=24),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
}

# CORS settings
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://formsite-client.onrender.com",
]

CORS_ALLOW_CREDENTIALS = True

# Rate limiting settings
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# Smart cache configuration - tries Redis, falls back to memory cache if Redis unavailable
try:
    import redis
    # Test Redis connection
    r = redis.Redis.from_url(os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/1'))
    r.ping()
    # Redis is available
    CACHES = {
        'default': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/1'),
            'OPTIONS': {
                'CLIENT_CLASS': 'django_redis.client.DefaultClient',
                'CONNECTION_POOL_KWARGS': {
                    'ssl_cert_reqs': None,
                }
            },
            'KEY_PREFIX': 'formsite',
            'TIMEOUT': 300,
        }
    }
    print("✅ Using Redis cache")
except:
    # Redis not available, use memory cache
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'unique-snowflake',
        }
    }
    print("⚠️ Redis not available, using memory cache")

# Email settings (optional for development)
if os.environ.get('EMAIL_HOST'):
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = os.environ.get('EMAIL_HOST')
    EMAIL_PORT = 587
    EMAIL_USE_TLS = True
    EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
    EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')
    DEFAULT_FROM_EMAIL = 'security@formsite.com'
else:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Data encryption settings
CRYPTOGRAPHY_KEY = os.environ.get('CRYPTOGRAPHY_KEY', secrets.token_urlsafe(32))

# Security monitoring settings
SECURITY_EMAIL_NOTIFICATIONS = not DEBUG
SECURITY_LOG_FAILED_LOGINS = True
SECURITY_LOG_SUSPICIOUS_ACTIVITY = True
SECURITY_IP_WHITELIST = os.environ.get('ADMIN_IP_WHITELIST', '127.0.0.1,localhost').split(',')

# Audit logging
AUDITLOG_INCLUDE_ALL_MODELS = True
AUDITLOG_EXCLUDE_TRACKING_MODELS = (
    'sessions.session',
    'admin.logentry',
    'contenttypes.contenttype',
    'auth.permission',
)

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple' if DEBUG else 'verbose',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'django.log',
            'formatter': 'verbose',
        } if not DEBUG else {
            'class': 'logging.NullHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'security_monitoring': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'auditlog': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
}

# Create logs directory if it doesn't exist
if not DEBUG:
    os.makedirs(BASE_DIR / 'logs', exist_ok=True)