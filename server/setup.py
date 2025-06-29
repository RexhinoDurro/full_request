
"""
Setup script for FormSite project with Python 3.11.9
Run this script to install dependencies and set up the project.
"""

import os
import sys
import subprocess
import platform

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"\n🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"Error: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    print(f"🐍 Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major != 3 or version.minor < 9:
        print("❌ Python 3.9+ is required")
        return False
    
    if version.minor == 11 and version.micro >= 9:
        print("✅ Python 3.11.9+ detected - compatible")
    elif version.minor >= 10:
        print("✅ Python 3.10+ detected - should be compatible")
    else:
        print("⚠️  Python 3.9 detected - may have compatibility issues")
    
    return True

def install_core_dependencies():
    """Install core dependencies that work with Python 3.11.9"""
    core_deps = [
        "Django==4.2.7",
        "djangorestframework==3.14.0",
        "djangorestframework-simplejwt==5.3.0",
        "django-cors-headers==4.3.1",
        "django-ratelimit==4.1.0",
        "whitenoise==6.6.0",
        "dj-database-url==2.1.0",
        "python-dotenv==1.0.0",
        "cryptography>=41.0.0",
        "gunicorn==21.2.0",
    ]
    
    for dep in core_deps:
        if not run_command(f"pip install {dep}", f"Installing {dep}"):
            return False
    
    return True

def install_optional_dependencies():
    """Install optional dependencies"""
    optional_deps = [
        ("psycopg[binary]>=3.1.0", "PostgreSQL support"),
        ("openpyxl>=3.1.0", "Excel export functionality"),
        ("bleach>=6.0.0", "HTML sanitization"),
        ("redis>=4.0.0", "Redis caching"),
        ("django-axes>=6.0.0", "Brute force protection"),
        ("django-csp>=3.7", "Content Security Policy"),
    ]
    
    print("\n🔧 Installing optional dependencies...")
    for dep, description in optional_deps:
        result = run_command(f"pip install {dep}", f"Installing {description}")
        if not result:
            print(f"⚠️  Optional dependency {dep} failed to install - continuing without it")

def create_env_file():
    """Create .env file with default settings"""
    env_content = """# Django Configuration
SECRET_KEY=your-secret-key-change-this-in-production
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database (optional - uses SQLite by default)
# DATABASE_URL=postgresql://user:password@localhost:5432/formsite

# CORS (add your frontend URLs)
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Email Configuration (optional)
# EMAIL_HOST=smtp.gmail.com
# EMAIL_PORT=587
# EMAIL_USE_TLS=True
# EMAIL_HOST_USER=your-email@gmail.com
# EMAIL_HOST_PASSWORD=your-app-password

# Encryption
CRYPTOGRAPHY_KEY=development-key-change-in-production

# Redis (optional)
# REDIS_URL=redis://localhost:6379/1
"""
    
    env_path = '.env'
    if not os.path.exists(env_path):
        with open(env_path, 'w') as f:
            f.write(env_content)
        print("✅ Created .env file with default settings")
    else:
        print("📝 .env file already exists - skipping")

def run_django_setup():
    """Run Django setup commands"""
    commands = [
        ("python manage.py makemigrations", "Creating database migrations"),
        ("python manage.py migrate", "Running database migrations"),
        ("python manage.py collectstatic --noinput", "Collecting static files"),
    ]
    
    for command, description in commands:
        if not run_command(command, description):
            return False
    
    return True

def create_superuser():
    """Create Django superuser"""
    print("\n👤 Creating superuser...")
    print("You can skip this step by pressing Ctrl+C")
    
    try:
        subprocess.run([
            sys.executable, "manage.py", "createsuperuser"
        ], check=True)
        print("✅ Superuser created successfully")
    except KeyboardInterrupt:
        print("\n⏭️  Skipped superuser creation")
    except subprocess.CalledProcessError:
        print("❌ Failed to create superuser")

def main():
    """Main setup function"""
    print("🚀 FormSite Python 3.11.9 Setup")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check if we're in the right directory
    if not os.path.exists('manage.py'):
        print("❌ manage.py not found. Please run this script from the Django project root.")
        sys.exit(1)
    
    # Install dependencies
    print("\n📦 Installing dependencies...")
    if not install_core_dependencies():
        print("❌ Failed to install core dependencies")
        sys.exit(1)
    
    install_optional_dependencies()
    
    # Create environment file
    print("\n⚙️  Setting up configuration...")
    create_env_file()
    
    # Run Django setup
    print("\n🗄️  Setting up database...")
    if not run_django_setup():
        print("❌ Django setup failed")
        sys.exit(1)
    
    # Create superuser
    create_superuser()
    
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Edit .env file with your configuration")
    print("2. Run: python manage.py runserver")
    print("3. Open: http://127.0.0.1:8000")
    print("\n📚 Admin panel: http://127.0.0.1:8000/admin/")
    print("🔗 API docs: http://127.0.0.1:8000/api/")

if __name__ == "__main__":
    main()