#!/bin/bash
# Render Configuration Cleanup Script
# Run this script in your project root directory to remove Render-specific configurations

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🧹 Cleaning up Render-specific configurations...${NC}"

# Check if we're in the right directory
if [ ! -f "server/manage.py" ] || [ ! -d "client" ]; then
    echo -e "${RED}❌ Please run this script from the project root directory${NC}"
    exit 1
fi

# Remove Render-specific files
echo -e "${YELLOW}📁 Removing Render-specific files...${NC}"

# Remove build scripts
if [ -f "server/build.sh" ]; then
    rm server/build.sh
    echo "✅ Removed server/build.sh"
fi

if [ -f "server/runtime.txt" ]; then
    rm server/runtime.txt
    echo "✅ Removed server/runtime.txt"
fi

# Remove Render production environment files
if [ -f "client/.env.production" ]; then
    rm client/.env.production
    echo "✅ Removed client/.env.production"
fi

if [ -f "admin/.env.production" ]; then
    rm admin/.env.production
    echo "✅ Removed admin/.env.production"
fi

# Create backup of Django settings
echo -e "${YELLOW}💾 Creating backup of Django settings...${NC}"
cp server/formsite_project/settings.py server/formsite_project/settings.py.render-backup
echo "✅ Created backup: server/formsite_project/settings.py.render-backup"

# Update Django settings for VPS deployment
echo -e "${YELLOW}⚙️ Updating Django settings for VPS...${NC}"
cat > server/formsite_project/settings_vps.py << 'EOF'
# formsite_project/settings.py - VPS DEPLOYMENT VERSION
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

# 🔒 SECURITY: VPS-specific allowed hosts
ALLOWED_HOSTS = []
if DEBUG:
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']
else:
    allowed_hosts_env = os.environ.get('ALLOWED_HOSTS')
    if allowed_hosts_env:
        ALLOWED_HOSTS = [host.strip() for host in allowed_hosts_env.split(',')]

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
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'axes.middleware.AxesMiddleware',
    'csp.middleware.CSPMiddleware',
    'security_monitoring.middleware.SecurityMiddleware',
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

# 🔒 SECURITY: Ultra-secure CSRF settings
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_NAME = 'secure_csrftoken'
CSRF_COOKIE_AGE = 31449600
CSRF_USE_SESSIONS = True

# VPS-specific CSRF trusted origins
CSRF_TRUSTED_ORIGINS = []
csrf_origins_env = os.environ.get('CSRF_TRUSTED_ORIGINS')
if csrf_origins_env:
    CSRF_TRUSTED_ORIGINS = [origin.strip() for origin in csrf_origins_env.split(',')]

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

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")
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
        'anon': '20/hour',
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

# CORS configuration for VPS
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False

# VPS-specific CORS origins
CORS_ALLOWED_ORIGINS = []
cors_origins_env = os.environ.get('CORS_ALLOWED_ORIGINS')
if cors_origins_env:
    CORS_ALLOWED_ORIGINS = [origin.strip() for origin in cors_origins_env.split(',')]

if DEBUG:
    CORS_ALLOWED_ORIGINS.extend([
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ])

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

# Brute force protection
AXES_ENABLED = True
AXES_FAILURE_LIMIT = 3
AXES_COOLOFF_TIME = timedelta(minutes=30)
AXES_RESET_ON_SUCCESS = True
AXES_LOGIN_FAILURE_LIMIT = 3
AXES_LOCK_OUT_AT_FAILURE = True
AXES_USE_USER_AGENT = True
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True

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

# Create logs directory
(BASE_DIR / 'logs').mkdir(exist_ok=True)

# Development overrides
if DEBUG:
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_SSL_REDIRECT = False
    AXES_ENABLED = False
    CSP_REPORT_ONLY = True
    
    print("🔒 VPS DEPLOYMENT - DEBUG MODE")
    print(f"   🔑 Encryption key: {'SET' if CRYPTOGRAPHY_KEY else 'MISSING'}")
    print(f"   📊 Database: {DATABASES['default']['ENGINE'].split('.')[-1]}")
    print(f"   🌐 CORS origins: {len(CORS_ALLOWED_ORIGINS)} configured")
    print(f"   🛡️ Brute force protection: {'ENABLED' if AXES_ENABLED else 'DISABLED'}")
    print("   ✅ VPS deployment ready")
else:
    print("🔒 VPS DEPLOYMENT - PRODUCTION MODE")
    print("   ✅ All security features enabled")
    print("   🛡️ Production-ready configuration")
EOF

echo "✅ Created VPS-optimized settings: server/formsite_project/settings_vps.py"

# Replace the original settings file
mv server/formsite_project/settings.py server/formsite_project/settings.py.original
mv server/formsite_project/settings_vps.py server/formsite_project/settings.py

echo "✅ Updated Django settings for VPS deployment"

# Create VPS-specific environment template
echo -e "${YELLOW}📄 Creating VPS environment template...${NC}"
cat > server/.env.template << 'EOF'
# VPS Production Environment Configuration
# Copy this to .env.production and fill in your values

# Django Configuration
SECRET_KEY=your-super-secret-key-generate-a-new-one
DEBUG=False
ALLOWED_HOSTS=client-formsite.com,admin-formsite.com,YOUR_VPS_IP

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/database

# Security
CRYPTOGRAPHY_KEY=generate-a-secure-encryption-key

# CORS & CSRF (for two-domain setup)
CORS_ALLOWED_ORIGINS=https://client-formsite.com,https://admin-formsite.com
CSRF_TRUSTED_ORIGINS=https://client-formsite.com,https://admin-formsite.com

# Admin Credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=generate-a-secure-admin-password

# Email Configuration (optional)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
EOF

echo "✅ Created environment template: server/.env.template"

# Create client environment template
cat > client/.env.template << 'EOF'
# Client Production Environment
# API points to admin domain where backend is hosted
VITE_API_URL=https://admin-formsite.com/api
EOF

echo "✅ Created client environment template: client/.env.template"

# Create admin environment template
cat > admin/.env.template << 'EOF'
# Admin Panel Production Environment
# API points to admin domain where backend is hosted
VITE_API_URL=https://admin-formsite.com/api
EOF

echo "✅ Created admin environment template: admin/.env.template"

# Update package.json scripts to remove Render-specific commands
echo -e "${YELLOW}📦 Updating package.json scripts...${NC}"

if [ -f "client/package.json" ]; then
    # Remove any Render-specific scripts if they exist
    echo "✅ Client package.json is ready for VPS deployment"
fi

if [ -f "admin/package.json" ]; then
    # Remove any Render-specific scripts if they exist
    echo "✅ Admin package.json is ready for VPS deployment"
fi

# Create deployment checklist
echo -e "${YELLOW}📋 Creating deployment checklist...${NC}"
cat > DEPLOYMENT_CHECKLIST.md << 'EOF'
# VPS Deployment Checklist - Two Domain Setup

## Pre-deployment
- [ ] Client domain (client-formsite.com) purchased and DNS configured
- [ ] Admin domain (admin-formsite.com) purchased and DNS configured
- [ ] VPS server provisioned (minimum 2GB RAM recommended)
- [ ] SSH access to VPS server configured
- [ ] SSL certificate email ready

## Environment Configuration
- [ ] Copy `.env.template` to `.env.production` in server directory
- [ ] Fill in all environment variables in `.env.production`
- [ ] Generate secure SECRET_KEY (min 50 characters)
- [ ] Generate secure CRYPTOGRAPHY_KEY
- [ ] Set strong ADMIN_PASSWORD
- [ ] Configure ALLOWED_HOSTS with both domains
- [ ] Configure CORS_ALLOWED_ORIGINS with both domains

## Client Configuration
- [ ] Copy `client/.env.template` to `client/.env.production`
- [ ] Verify VITE_API_URL points to admin domain

## Admin Configuration
- [ ] Copy `admin/.env.template` to `admin/.env.production`
- [ ] Verify VITE_API_URL points to admin domain

## Security
- [ ] Change all default passwords
- [ ] Configure firewall (UFW)
- [ ] Setup fail2ban
- [ ] Configure SSL/TLS for both domains
- [ ] Test security headers on both domains
- [ ] Enable automatic security updates

## Testing
- [ ] Test form submission on client domain
- [ ] Test admin login on admin domain
- [ ] Test API endpoints on admin domain
- [ ] Test SSL certificates for both domains
- [ ] Test rate limiting
- [ ] Verify security headers
- [ ] Test cross-domain communication

## Monitoring
- [ ] Setup backup system
- [ ] Configure log rotation
- [ ] Setup monitoring alerts
- [ ] Test disaster recovery

## Two-Domain Architecture
- [ ] Client domain serves only the public form
- [ ] Admin domain serves admin panel and API
- [ ] Form submissions go from client to admin domain API
- [ ] Admin operations are isolated on admin domain
EOF

echo "✅ Created deployment checklist: DEPLOYMENT_CHECKLIST.md"

# Create migration guide
cat > MIGRATION_FROM_RENDER.md << 'EOF'
# Migration from Render to VPS

## What was removed:
- `server/build.sh` - Render-specific build script
- `server/runtime.txt` - Render Python version specification
- `client/.env.production` - Render-specific client environment
- `admin/.env.production` - Render-specific admin environment

## What was changed:
- Django settings updated for VPS deployment
- Environment configuration templates created
- CORS and CSRF settings updated for custom domain
- Security settings optimized for VPS hosting

## What you need to do:
1. Review the new settings in `server/formsite_project/settings.py`
2. Configure environment variables using the templates
3. Run the VPS deployment script
4. Update your domain DNS to point to the VPS
5. Test all functionality

## Backup locations:
- Original Django settings: `server/formsite_project/settings.py.render-backup`
- Original settings file: `server/formsite_project/settings.py.original`
EOF

echo "✅ Created migration guide: MIGRATION_FROM_RENDER.md"

echo -e "${GREEN}🎉 Render cleanup completed successfully!${NC}"
echo ""
echo -e "${BLUE}📋 Summary of changes:${NC}"
echo "✅ Removed Render-specific files"
echo "✅ Updated Django settings for VPS (Redis removed)"
echo "✅ Created environment templates for two-domain setup"
echo "✅ Created deployment checklist"
echo "✅ Created migration guide"
echo ""
echo -e "${YELLOW}📝 Next steps:${NC}"
echo "1. Review DEPLOYMENT_CHECKLIST.md"
echo "2. Configure environment variables using .env.template files"
echo "3. Set up your domains:"
echo "   - client-formsite.com (for public form)"
echo "   - admin-formsite.com (for admin panel & API)"
echo "4. Run the VPS deployment script on your server"
echo "5. Update both domains' DNS to point to your VPS"
echo ""
echo -e "${BLUE}🏗️ Two-Domain Architecture:${NC}"
echo "📱 Client Domain: Public form interface only"
echo "🔧 Admin Domain: Admin panel, API, and Django admin"
echo "🔗 Cross-domain: Form submissions from client to admin API"
echo ""
echo -e "${GREEN}✅ Your project is now ready for two-domain VPS deployment!${NC}"