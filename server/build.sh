#!/usr/bin/env bash
# Exit on error
set -o errexit

echo "Starting build process..."

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Run database migrations
echo "Running database migrations..."
python manage.py migrate

# Create admin user if it doesn't exist
echo "Setting up admin user..."
python manage.py shell -c "
from django.contrib.auth.models import User
import os

admin_username = 'admin'
admin_email = 'admin@formsite.com'
admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')

if not User.objects.filter(username=admin_username).exists():
    User.objects.create_superuser(admin_username, admin_email, admin_password)
    print(f'Admin user \"{admin_username}\" created successfully')
else:
    print(f'Admin user \"{admin_username}\" already exists')
"

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Build process completed successfully!"