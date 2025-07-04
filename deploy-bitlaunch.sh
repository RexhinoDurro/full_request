#!/bin/bash
# BitLaunch VPS Deployment Script for FormSite Application
# Domains: formsite-client.eu (client) and formsite-admin.eu (admin + API)
# Server IP: 206.71.149.194

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CLIENT_DOMAIN="formsite-client.eu"
ADMIN_DOMAIN="formsite-admin.eu"
SERVER_IP="206.71.149.194"
EMAIL="admin@${CLIENT_DOMAIN}"
APP_USER="formsite"
APP_DIR="/home/formsite/formsite-app"
DB_NAME="formsite_db"
DB_USER="formsite_user"

echo -e "${BLUE}🚀 FormSite BitLaunch VPS Deployment${NC}"
echo "========================================"
echo "Client Domain: ${CLIENT_DOMAIN}"
echo "Admin Domain: ${ADMIN_DOMAIN}"
echo "Server IP: ${SERVER_IP}"
echo ""

# Generate secure credentials
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

DB_PASSWORD=$(generate_password)
SECRET_KEY=$(openssl rand -base64 64 | tr -d "=+/" | cut -c1-50)
CRYPTO_KEY=$(openssl rand -base64 32)
ADMIN_PASSWORD=$(generate_password)

# Update system
echo -e "${BLUE}📦 Updating system packages...${NC}"
apt update && apt upgrade -y

# Install dependencies
echo -e "${BLUE}📦 Installing dependencies...${NC}"
apt install -y python3 python3-pip python3-venv nginx postgresql postgresql-contrib \
    git ufw fail2ban certbot python3-certbot-nginx software-properties-common \
    curl build-essential

# Install Node.js 18.x
echo -e "${BLUE}📦 Installing Node.js...${NC}"
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
apt install -y nodejs

# Create application user
echo -e "${BLUE}👤 Creating application user...${NC}"
if ! id "$APP_USER" &>/dev/null; then
    adduser --disabled-password --gecos "" $APP_USER
    usermod -aG sudo $APP_USER
fi

# Clone repository (assuming it's already uploaded to the server)
echo -e "${BLUE}📁 Setting up application directory...${NC}"
sudo -u $APP_USER bash << EOF
cd /home/$APP_USER
if [ ! -d 'formsite-app' ]; then
    echo "Please upload your application code to /home/$APP_USER/formsite-app"
    exit 1
fi
cd formsite-app
EOF

# Setup PostgreSQL
echo -e "${BLUE}🗄️ Setting up PostgreSQL...${NC}"
sudo -u postgres psql << EOF
DROP DATABASE IF EXISTS $DB_NAME;
DROP USER IF EXISTS $DB_USER;
CREATE DATABASE $DB_NAME;
CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
ALTER USER $DB_USER CREATEDB;
EOF

# Setup Django backend
echo -e "${BLUE}🐍 Setting up Django backend...${NC}"
sudo -u $APP_USER bash << EOF
cd $APP_DIR/server
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create production environment
cat > .env.production << ENVEOF
SECRET_KEY=$SECRET_KEY
DEBUG=False
ALLOWED_HOSTS=$CLIENT_DOMAIN,$ADMIN_DOMAIN,$SERVER_IP
DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME
CRYPTOGRAPHY_KEY=$CRYPTO_KEY
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$ADMIN_PASSWORD
CORS_ALLOWED_ORIGINS=https://$CLIENT_DOMAIN,https://$ADMIN_DOMAIN
CSRF_TRUSTED_ORIGINS=https://$CLIENT_DOMAIN,https://$ADMIN_DOMAIN
ENVEOF

chmod 600 .env.production

# Set environment and run Django setup
export \$(cat .env.production | xargs)
python manage.py migrate
python manage.py collectstatic --noinput

# Create superuser
echo "from django.contrib.auth.models import User; User.objects.create_superuser('admin', '$EMAIL', '$ADMIN_PASSWORD')" | python manage.py shell || true
EOF

# Setup React client
echo -e "${BLUE}⚛️ Setting up React client...${NC}"
sudo -u $APP_USER bash << EOF
cd $APP_DIR/client
npm install

cat > .env.production << ENVEOF
VITE_API_URL=https://$ADMIN_DOMAIN/api
ENVEOF

npm run build
EOF

# Setup React admin
echo -e "${BLUE}⚛️ Setting up React admin...${NC}"
sudo -u $APP_USER bash << EOF
cd $APP_DIR/admin
npm install

cat > .env.production << ENVEOF
VITE_API_URL=https://$ADMIN_DOMAIN/api
ENVEOF

npm run build
EOF

# Create systemd service
echo -e "${BLUE}⚙️ Creating systemd service...${NC}"
cat > /etc/systemd/system/formsite.service << EOF
[Unit]
Description=Formsite Gunicorn daemon
Requires=formsite.socket
After=network.target

[Service]
Type=notify
User=$APP_USER
Group=$APP_USER
RuntimeDirectory=formsite
WorkingDirectory=$APP_DIR/server
Environment=DJANGO_SETTINGS_MODULE=formsite_project.settings
EnvironmentFile=$APP_DIR/server/.env.production
ExecStart=$APP_DIR/server/venv/bin/gunicorn \\
    --access-logfile - \\
    --workers 3 \\
    --bind unix:/run/formsite/formsite.sock \\
    formsite_project.wsgi:application
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/formsite.socket << EOF
[Unit]
Description=formsite socket

[Socket]
ListenStream=/run/formsite/formsite.sock
SocketUser=www-data

[Install]
WantedBy=sockets.target
EOF

# Create Nginx configuration
echo -e "${BLUE}🌐 Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/formsite << EOF
# Rate limiting zones
limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone \$binary_remote_addr zone=submit:10m rate=2r/m;
limit_req_zone \$binary_remote_addr zone=admin:10m rate=50r/h;

upstream formsite_backend {
    server unix:/run/formsite/formsite.sock fail_timeout=30s max_fails=3;
}

# CLIENT DOMAIN HTTP to HTTPS redirect
server {
    listen 80;
    server_name $CLIENT_DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

# ADMIN DOMAIN HTTP to HTTPS redirect
server {
    listen 80;
    server_name $ADMIN_DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

# CLIENT DOMAIN - Public Form Interface
server {
    listen 443 ssl http2;
    server_name $CLIENT_DOMAIN;

    # Temporary SSL certificates (will be replaced by Let's Encrypt)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    server_tokens off;
    client_max_body_size 10M;

    # Serve React client app
    location / {
        root $APP_DIR/client/dist;
        try_files \$uri \$uri/ /index.html;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Allow form submissions from client domain to admin domain API
    location /api/submit/ {
        limit_req zone=submit burst=1 nodelay;
        proxy_pass http://formsite_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Block other API endpoints on client domain
    location /api/ {
        return 403;
    }

    location /admin/ {
        return 403;
    }

    # Static files
    location /static/ {
        alias $APP_DIR/server/staticfiles/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}

# ADMIN DOMAIN - Admin Panel and Full API
server {
    listen 443 ssl http2;
    server_name $ADMIN_DOMAIN;

    # Temporary SSL certificates (will be replaced by Let's Encrypt)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    server_tokens off;
    client_max_body_size 10M;

    # Serve React admin app
    location / {
        root $APP_DIR/admin/dist;
        try_files \$uri \$uri/ /index.html;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://formsite_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Django admin
    location /admin/ {
        proxy_pass http://formsite_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Static files
    location /static/ {
        alias $APP_DIR/server/staticfiles/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/formsite /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx configuration
nginx -t

# Setup firewall
echo -e "${BLUE}🔥 Configuring firewall...${NC}"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 'Nginx Full'
ufw --force enable

# Setup fail2ban
echo -e "${BLUE}🛡️ Configuring fail2ban...${NC}"
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
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
EOF

# Create runtime directory
mkdir -p /run/formsite
chown $APP_USER:www-data /run/formsite

# Start services
echo -e "${BLUE}🚀 Starting services...${NC}"
systemctl daemon-reload
systemctl enable formsite.socket
systemctl start formsite.socket
systemctl enable formsite.service
systemctl start formsite.service
systemctl enable nginx
systemctl restart nginx
systemctl enable postgresql
systemctl restart postgresql
systemctl enable fail2ban
systemctl restart fail2ban

# Setup SSL certificates
echo -e "${BLUE}🔐 Setting up SSL certificates...${NC}"
certbot --nginx -d $CLIENT_DOMAIN -d $ADMIN_DOMAIN --email $EMAIL --agree-tos --non-interactive

# Create backup script
echo -e "${BLUE}💾 Setting up backup system...${NC}"
sudo -u $APP_USER bash << EOF
cat > /home/$APP_USER/backup.sh << 'BACKUPEOF'
#!/bin/bash
BACKUP_DIR="/home/$APP_USER/backups"
DATE=\$(date +%Y%m%d_%H%M%S)

mkdir -p \$BACKUP_DIR

# Database backup
sudo -u postgres pg_dump $DB_NAME > \$BACKUP_DIR/db_backup_\$DATE.sql

# Application backup
tar -czf \$BACKUP_DIR/app_backup_\$DATE.tar.gz $APP_DIR

# Keep only last 7 days
find \$BACKUP_DIR -name '*.sql' -mtime +7 -delete
find \$BACKUP_DIR -name '*.tar.gz' -mtime +7 -delete

echo "Backup completed: \$DATE"
BACKUPEOF

chmod +x /home/$APP_USER/backup.sh
EOF

# Setup daily backup cron
sudo -u $APP_USER bash -c "(crontab -l 2>/dev/null; echo '0 2 * * * /home/$APP_USER/backup.sh') | crontab -"

# Final service check
echo -e "${BLUE}🔍 Checking service status...${NC}"
systemctl status formsite.service --no-pager
systemctl status nginx --no-pager

echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
echo "=========================================="
echo -e "${BLUE}📋 Deployment Summary:${NC}"
echo "Client Domain: https://$CLIENT_DOMAIN"
echo "Admin Domain: https://$ADMIN_DOMAIN"
echo "Django Admin: https://$ADMIN_DOMAIN/admin/"
echo "API Endpoints: https://$ADMIN_DOMAIN/api/"
echo ""
echo -e "${BLUE}🔐 Admin Credentials:${NC}"
echo "Username: admin"
echo "Password: $ADMIN_PASSWORD"
echo ""
echo -e "${BLUE}🔑 Database Credentials:${NC}"
echo "Database: $DB_NAME"
echo "User: $DB_USER"
echo "Password: $DB_PASSWORD"
echo ""
echo -e "${BLUE}🔑 Important Keys (SAVE THESE):${NC}"
echo "Secret Key: $SECRET_KEY"
echo "Crypto Key: $CRYPTO_KEY"
echo ""
echo -e "${YELLOW}⚠️ Next Steps:${NC}"
echo "1. Save all credentials securely"
echo "2. Test your applications:"
echo "   - Client: https://$CLIENT_DOMAIN"
echo "   - Admin: https://$ADMIN_DOMAIN"
echo "3. DNS propagation may take up to 24 hours"
echo "4. Backup script runs daily at 2 AM"
echo ""
echo -e "${GREEN}✅ Your FormSite application is now live!${NC}"