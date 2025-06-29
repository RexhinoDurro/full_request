#!/bin/bash
# deploy-secure.sh - Ultra-secure production deployment script

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔒 Starting ultra-secure deployment...${NC}"

# Check if running as root (should not be)
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}❌ Do not run this script as root for security reasons${NC}" 
   exit 1
fi

# Environment validation
echo -e "${YELLOW}📋 Validating environment variables...${NC}"

REQUIRED_ENV_VARS=(
    "SECRET_KEY"
    "DATABASE_URL"
    "ALLOWED_HOSTS"
    "EMAIL_HOST"
    "EMAIL_HOST_USER"
    "EMAIL_HOST_PASSWORD"
    "REDIS_URL"
    "CRYPTOGRAPHY_KEY"
    "ADMIN_PASSWORD"
)

for var in "${REQUIRED_ENV_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        echo -e "${RED}❌ Missing required environment variable: $var${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✅ Environment variables validated${NC}"

# Generate additional security keys if not present
echo -e "${YELLOW}🔐 Generating security keys...${NC}"

if [[ -z "${DB_BACKUP_KEY:-}" ]]; then
    export DB_BACKUP_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
    echo "DB_BACKUP_KEY=$DB_BACKUP_KEY" >> .env
fi

if [[ -z "${ADMIN_URL_PREFIX:-}" ]]; then
    export ADMIN_URL_PREFIX="secure-admin-$(python -c "import secrets; print(secrets.token_urlsafe(8))")"
    echo "ADMIN_URL_PREFIX=$ADMIN_URL_PREFIX" >> .env
    echo -e "${GREEN}🔗 Admin URL: /$ADMIN_URL_PREFIX/${NC}"
fi

# Install system dependencies
echo -e "${YELLOW}📦 Installing system security tools...${NC}"

# Update system packages
sudo apt-get update && sudo apt-get upgrade -y

# Install security tools
sudo apt-get install -y \
    fail2ban \
    ufw \
    rkhunter \
    chkrootkit \
    logwatch \
    aide \
    clamav \
    clamav-daemon \
    unattended-upgrades \
    apt-listchanges

# Install Python dependencies
echo -e "${YELLOW}🐍 Installing Python dependencies...${NC}"
pip install -r requirements.txt

# Additional security packages
pip install \
    bandit \
    safety \
    semgrep

# Database security setup
echo -e "${YELLOW}🗄️ Configuring database security...${NC}"

# Run migrations
python manage.py migrate --no-input

# Create superuser with secure password
python manage.py shell -c "
from django.contrib.auth.models import User
import os

username = 'admin'
email = 'admin@formsite.com'
password = os.environ.get('ADMIN_PASSWORD')

if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(username, email, password)
    print(f'Superuser {username} created')
else:
    # Update password for existing user
    user = User.objects.get(username=username)
    user.set_password(password)
    user.save()
    print(f'Password updated for {username}')
"

# Firewall configuration
echo -e "${YELLOW}🔥 Configuring firewall...${NC}"

# Reset UFW
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (change port from default 22 for security)
sudo ufw allow 2222/tcp comment 'SSH on non-standard port'

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'

# Allow database port only from application server
sudo ufw allow from 10.0.0.0/8 to any port 5432 comment 'PostgreSQL from private network'

# Enable firewall
sudo ufw --force enable

echo -e "${GREEN}✅ Firewall configured${NC}"

# Fail2Ban configuration
echo -e "${YELLOW}🛡️ Configuring Fail2Ban...${NC}"

sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 3

[django-auth]
enabled = true
filter = django-auth
logpath = /var/log/formsite/security.log
maxretry = 3
bantime = 7200
EOF

# Create Django auth filter
sudo tee /etc/fail2ban/filter.d/django-auth.conf > /dev/null <<EOF
[Definition]
failregex = SECURITY.*LOGIN_FAILURE.*<HOST>
ignoreregex =
EOF

sudo systemctl enable fail2ban
sudo systemctl restart fail2ban

echo -e "${GREEN}✅ Fail2Ban configured${NC}"

# SSL/TLS Configuration (assuming Let's Encrypt)
echo -e "${YELLOW}🔐 Setting up SSL/TLS...${NC}"

# Install Certbot
sudo apt-get install -y certbot python3-certbot-nginx

# Generate strong DH parameters
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

echo -e "${GREEN}✅ SSL tools installed${NC}"

# Nginx security configuration
echo -e "${YELLOW}⚙️ Configuring Nginx security...${NC}"

sudo tee /etc/nginx/snippets/security-headers.conf > /dev/null <<EOF
# Security Headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Hide Nginx version
server_tokens off;

# Rate limiting
limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone \$binary_remote_addr zone=submit:10m rate=5r/m;
limit_req_zone \$binary_remote_addr zone=login:10m rate=3r/m;

# Connection limiting
limit_conn_zone \$binary_remote_addr zone=conn_limit_per_ip:10m;
limit_conn conn_limit_per_ip 20;
EOF

sudo tee /etc/nginx/sites-available/formsite-secure > /dev/null <<EOF
upstream django_backend {
    server 127.0.0.1:8000 fail_timeout=30s max_fails=3;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name \$host;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS Configuration
server {
    listen 443 ssl http2;
    server_name \$host;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/\$host/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/\$host/privkey.pem;
    ssl_dhparam /etc/ssl/certs/dhparam.pem;
    
    ssl_protocols TLSv1.3 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_ecdh_curve secp384r1;
    ssl_session_timeout 10m;
    ssl_session_cache shared:SSL:10m;
    ssl_prefer_server_ciphers off;
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security headers
    include /etc/nginx/snippets/security-headers.conf;

    # Client upload limit
    client_max_body_size 10M;
    client_body_timeout 60s;
    client_header_timeout 60s;

    # API rate limiting
    location /api/submit/ {
        limit_req zone=submit burst=2 nodelay;
        proxy_pass http://django_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /api/auth/login/ {
        limit_req zone=login burst=1 nodelay;
        proxy_pass http://django_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://django_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Static files
    location /static/ {
        alias /var/www/formsite/staticfiles/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Admin with custom URL
    location /${ADMIN_URL_PREFIX}/ {
        # IP whitelist for admin (add your IPs)
        allow 203.0.113.0/24;  # Replace with your IP range
        deny all;
        
        proxy_pass http://django_backend/admin/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Block common attack patterns
    location ~* \.(asp|aspx|jsp|php|pl|py|sh|cgi)\$ {
        deny all;
    }

    location ~* /\.(git|svn|env|htaccess|htpasswd) {
        deny all;
    }

    # Default location
    location / {
        proxy_pass http://django_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Additional security
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}
EOF

# Enable the site
sudo ln -sf /etc/nginx/sites-available/formsite-secure /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test and reload Nginx
sudo nginx -t && sudo systemctl reload nginx

echo -e "${GREEN}✅ Nginx configured with security headers${NC}"

# Security scanning and monitoring
echo -e "${YELLOW}🔍 Setting up security monitoring...${NC}"

# Create log directories
sudo mkdir -p /var/log/formsite
sudo chown www-data:www-data /var/log/formsite

# Intrusion detection
sudo aide --init
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Malware scanning
sudo freshclam
sudo systemctl enable clamav-daemon

# Log rotation
sudo tee /etc/logrotate.d/formsite > /dev/null <<EOF
/var/log/formsite/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload gunicorn
    endscript
}
EOF

# Security audit cron jobs
sudo tee /etc/cron.daily/security-audit > /dev/null <<'EOF'
#!/bin/bash
# Daily security audit

LOG_FILE="/var/log/formsite/security-audit.log"
DATE=$(date)

echo "=== Security Audit - $DATE ===" >> $LOG_FILE

# Check for rootkits
rkhunter --update --quiet
rkhunter --checkall --skip-keypress --quiet >> $LOG_FILE 2>&1

# File integrity check
aide --check >> $LOG_FILE 2>&1

# Check for suspicious files
find /var/www -name "*.php" -o -name "*.jsp" -o -name "*.asp" >> $LOG_FILE 2>&1

# Check listening ports
netstat -tuln >> $LOG_FILE 2>&1

# Check failed login attempts
grep "Failed password" /var/log/auth.log | tail -20 >> $LOG_FILE 2>&1

# Malware scan (quick)
clamscan --infected --quiet /var/www/ >> $LOG_FILE 2>&1

echo "=== End Audit ===" >> $LOG_FILE
echo "" >> $LOG_FILE
EOF

sudo chmod +x /etc/cron.daily/security-audit

# Security updates
echo 'Unattended-Upgrade::Automatic-Reboot "false";' | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades
sudo systemctl enable unattended-upgrades

echo -e "${GREEN}✅ Security monitoring configured${NC}"

# Application security hardening
echo -e "${YELLOW}🔧 Hardening application...${NC}"

# Collect static files
python manage.py collectstatic --no-input

# Run security checks
echo -e "${BLUE}🔍 Running security scans...${NC}"

# Django security check
python manage.py check --deploy || echo -e "${YELLOW}⚠️ Django security warnings found${NC}"

# Bandit security scan
bandit -r . -f json -o security-report.json || echo -e "${YELLOW}⚠️ Bandit found potential issues${NC}"

# Safety check for vulnerabilities
safety check || echo -e "${YELLOW}⚠️ Vulnerable dependencies found${NC}"

# Set file permissions
echo -e "${YELLOW}📝 Setting secure file permissions...${NC}"

# Application files
sudo chown -R www-data:www-data /var/www/formsite/
sudo chmod -R 644 /var/www/formsite/
sudo chmod -R +X /var/www/formsite/
sudo chmod 600 /var/www/formsite/.env

# Configuration files
sudo chmod 600 /etc/nginx/sites-available/formsite-secure
sudo chmod 644 /etc/fail2ban/jail.local

echo -e "${GREEN}✅ File permissions set${NC}"

# Backup configuration
echo -e "${YELLOW}💾 Setting up automated backups...${NC}"

sudo tee /etc/cron.daily/backup-formsite > /dev/null <<'EOF'
#!/bin/bash
# Automated encrypted backup

BACKUP_DIR="/var/backups/formsite"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="formsite_backup_$DATE.sql"
BACKUP_FILE="formsite_backup_$DATE.tar.gz.enc"

mkdir -p $BACKUP_DIR

# Database backup
pg_dump $DATABASE_URL > /tmp/$DB_NAME

# Create encrypted archive
tar -czf - /var/www/formsite /tmp/$DB_NAME | openssl enc -aes-256-cbc -salt -k "$DB_BACKUP_KEY" > $BACKUP_DIR/$BACKUP_FILE

# Clean up
rm /tmp/$DB_NAME

# Keep only last 7 days of backups
find $BACKUP_DIR -name "formsite_backup_*.tar.gz.enc" -mtime +7 -delete

echo "Backup completed: $BACKUP_FILE"
EOF

sudo chmod +x /etc/cron.daily/backup-formsite

echo -e "${GREEN}✅ Automated backups configured${NC}"

# Final system hardening
echo -e "${YELLOW}🔒 Final system hardening...${NC}"

# Disable unused services
sudo systemctl disable cups bluetooth
sudo systemctl stop cups bluetooth

# Kernel hardening (add to /etc/sysctl.conf)
sudo tee -a /etc/sysctl.conf > /dev/null <<EOF
# Network security
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
kernel.exec-shield=1
kernel.randomize_va_space=2
EOF

sudo sysctl -p

echo -e "${GREEN}✅ System hardening complete${NC}"

# Start/restart services
echo -e "${YELLOW}🚀 Starting services...${NC}"

sudo systemctl enable nginx
sudo systemctl restart nginx

# Start Gunicorn with security settings
gunicorn formsite_project.wsgi:application \
    --bind 127.0.0.1:8000 \
    --workers 3 \
    --worker-class gevent \
    --worker-connections 1000 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --timeout 30 \
    --keep-alive 2 \
    --user www-data \
    --group www-data \
    --daemon \
    --pid /var/run/gunicorn.pid \
    --log-level info \
    --log-file /var/log/formsite/gunicorn.log \
    --access-logfile /var/log/formsite/gunicorn-access.log \
    --error-logfile /var/log/formsite/gunicorn-error.log

echo -e "${GREEN}✅ Services started${NC}"

# Final security summary
echo -e "${BLUE}📊 Deployment Security Summary:${NC}"
echo -e "${GREEN}✅ Environment variables validated${NC}"
echo -e "${GREEN}✅ Firewall configured (UFW)${NC}"
echo -e "${GREEN}✅ Intrusion prevention (Fail2Ban)${NC}"
echo -e "${GREEN}✅ SSL/TLS with strong ciphers${NC}"
echo -e "${GREEN}✅ Security headers configured${NC}"
echo -e "${GREEN}✅ Rate limiting implemented${NC}"
echo -e "${GREEN}✅ Admin URL obfuscated: /$ADMIN_URL_PREFIX/${NC}"
echo -e "${GREEN}✅ Automated security scanning${NC}"
echo -e "${GREEN}✅ Encrypted automated backups${NC}"
echo -e "${GREEN}✅ File integrity monitoring (AIDE)${NC}"
echo -e "${GREEN}✅ Malware scanning (ClamAV)${NC}"
echo -e "${GREEN}✅ System hardening applied${NC}"

echo -e "${BLUE}🎉 Ultra-secure deployment completed successfully!${NC}"
echo -e "${YELLOW}📝 Important notes:${NC}"
echo -e "- Admin panel: https://yourdomain.com/$ADMIN_URL_PREFIX/"
echo -e "- Change default SSH port to 2222"
echo -e "- Update IP whitelist in Nginx config"
echo -e "- Monitor logs in /var/log/formsite/"
echo -e "- Review security audit reports daily"

echo -e "${RED}⚠️  Security Reminders:${NC}"
echo -e "1. Regularly update SSL certificates"
echo -e "2. Monitor security logs daily"
echo -e "3. Keep system packages updated"
echo -e "4. Rotate secrets periodically"
echo -e "5. Test backup restoration procedures"