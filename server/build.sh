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

# Create admin users
echo "Setting up admin users..."
python manage.py shell -c "
from django.contrib.auth.models import User
import os

# Primary admin user
admin_username = 'admin'
admin_email = 'admin@formsite.com'
admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')

if not User.objects.filter(username=admin_username).exists():
    User.objects.create_superuser(admin_username, admin_email, admin_password)
    print(f'Admin user \"{admin_username}\" created successfully')
else:
    print(f'Admin user \"{admin_username}\" already exists')

# Optional: Create a second admin user
admin2_username = os.environ.get('ADMIN2_USERNAME')
admin2_email = os.environ.get('ADMIN2_EMAIL')
admin2_password = os.environ.get('ADMIN2_PASSWORD')

if admin2_username and admin2_email and admin2_password:
    if not User.objects.filter(username=admin2_username).exists():
        User.objects.create_superuser(admin2_username, admin2_email, admin2_password)
        print(f'Second admin user \"{admin2_username}\" created successfully')
    else:
        print(f'Second admin user \"{admin2_username}\" already exists')
"

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Build process completed successfully!"