#!/usr/bin/env bash
# Exit on error
set -o errexit

echo "🚀 Starting secure deployment..."

# Validate required environment variables
REQUIRED_VARS=("SECRET_KEY" "CRYPTOGRAPHY_KEY" "ADMIN_PASSWORD")
for var in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!var}" ]]; then
        echo "❌ ERROR: Required environment variable '$var' is not set"
        exit 1
    fi
done

# Validate password strength
if [[ ${#ADMIN_PASSWORD} -lt 12 ]]; then
    echo "❌ ERROR: ADMIN_PASSWORD must be at least 12 characters long"
    exit 1
fi

# Install dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Run database migrations
echo "🗄️ Running database migrations..."
python manage.py migrate --noinput

# Collect static files
echo "📁 Collecting static files..."
python manage.py collectstatic --noinput

# Create superuser securely
echo "👤 Setting up admin user..."
python manage.py shell -c "
from django.contrib.auth.models import User
import os
import sys

admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
admin_email = os.environ.get('ADMIN_EMAIL', 'admin@formsite.com')
admin_password = os.environ.get('ADMIN_PASSWORD')

# Validate inputs
if not admin_password:
    print('❌ ADMIN_PASSWORD environment variable is required')
    sys.exit(1)

if len(admin_password) < 12:
    print('❌ ADMIN_PASSWORD must be at least 12 characters long')
    sys.exit(1)

# Check password complexity
import re
if not re.search(r'[A-Z]', admin_password):
    print('❌ ADMIN_PASSWORD must contain at least one uppercase letter')
    sys.exit(1)

if not re.search(r'[a-z]', admin_password):
    print('❌ ADMIN_PASSWORD must contain at least one lowercase letter')
    sys.exit(1)

if not re.search(r'\d', admin_password):
    print('❌ ADMIN_PASSWORD must contain at least one digit')
    sys.exit(1)

if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', admin_password):
    print('❌ ADMIN_PASSWORD must contain at least one special character')
    sys.exit(1)

# Create or update admin user
if not User.objects.filter(username=admin_username).exists():
    User.objects.create_superuser(admin_username, admin_email, admin_password)
    print(f'✅ Admin user \"{admin_username}\" created successfully')
else:
    # Update existing user password for security
    user = User.objects.get(username=admin_username)
    user.set_password(admin_password)
    user.save()
    print(f'✅ Admin user \"{admin_username}\" password updated')
"

# Security check
echo "🔒 Running security checks..."
python manage.py check --deploy --fail-level WARNING

# Create logs directory
mkdir -p logs

echo "✅ Secure build completed successfully!"
echo ""
echo "🛡️  Security Notes:"
echo "- Admin user created with strong password"
echo "- All required environment variables validated"
echo "- Security checks passed"
echo "- No default credentials exposed"