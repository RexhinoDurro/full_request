# submissions/management/commands/create_anonymous_admin.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
import secrets
import string
import os

class Command(BaseCommand):
    help = 'Create anonymous admin user for secure access'

    def add_arguments(self, parser):
        parser.add_argument(
            '--regenerate',
            action='store_true',
            help='Regenerate admin credentials',
        )
        parser.add_argument(
            '--username',
            type=str,
            help='Custom username (optional)',
        )

    def handle(self, *args, **options):
        self.stdout.write("👤 Setting up anonymous admin access...")
        
        # Generate secure random credentials
        def generate_secure_string(length=12, include_symbols=False):
            """Generate cryptographically secure random string"""
            if include_symbols:
                chars = string.ascii_letters + string.digits + "!@#$%^&*"
            else:
                chars = string.ascii_letters + string.digits
            return ''.join(secrets.choice(chars) for _ in range(length))
        
        # Generate anonymous credentials
        if options['username']:
            admin_username = options['username']
        else:
            # Generate anonymous username
            adjectives = ['secure', 'hidden', 'shadow', 'silent', 'ghost', 'anon', 'safe', 'guard']
            nouns = ['admin', 'user', 'keeper', 'watch', 'shield', 'gate', 'lock', 'key']
            
            random_adj = secrets.choice(adjectives)
            random_noun = secrets.choice(nouns)
            random_num = secrets.randbelow(9999)
            
            admin_username = f"{random_adj}_{random_noun}_{random_num}"
        
        # Generate secure email and password
        admin_email = f"{generate_secure_string(8)}@secure.local"
        admin_password = generate_secure_string(16, include_symbols=True)
        
        try:
            # Check if we need to regenerate
            if options['regenerate']:
                # Delete existing admin users
                User.objects.filter(is_superuser=True).delete()
                self.stdout.write("🗑️ Removed existing admin users")
            
            # Create or update admin user
            if User.objects.filter(username=admin_username).exists():
                user = User.objects.get(username=admin_username)
                user.set_password(admin_password)
                user.email = admin_email
                user.is_staff = True
                user.is_superuser = True
                user.save()
                self.stdout.write(f"🔄 Updated existing admin user: {admin_username}")
            else:
                User.objects.create_superuser(
                    username=admin_username,
                    email=admin_email,
                    password=admin_password
                )
                self.stdout.write(f"✅ Created new anonymous admin user: {admin_username}")
            
            # Display credentials securely
            self.stdout.write("")
            self.stdout.write("🔐 ANONYMOUS ADMIN CREDENTIALS:")
            self.stdout.write("=" * 50)
            self.stdout.write(f"Username: {admin_username}")
            self.stdout.write(f"Email: {admin_email}")
            self.stdout.write(f"Password: {admin_password}")
            self.stdout.write("=" * 50)
            self.stdout.write("")
            self.stdout.write("⚠️  SECURITY NOTES:")
            self.stdout.write("- Save these credentials in a secure password manager")
            self.stdout.write("- These credentials are randomly generated for anonymity")
            self.stdout.write("- Access the admin panel at: /admin/")
            self.stdout.write("- Admin actions are logged for security")
            self.stdout.write("- Consider using a VPN for additional anonymity")
            self.stdout.write("")
            
            # Create environment file with credentials
            env_file = '.admin_credentials'
            with open(env_file, 'w') as f:
                f.write(f"# Anonymous Admin Credentials\n")
                f.write(f"# Generated on: {secrets.token_hex(8)}\n")
                f.write(f"ADMIN_USERNAME={admin_username}\n")
                f.write(f"ADMIN_EMAIL={admin_email}\n")
                f.write(f"ADMIN_PASSWORD={admin_password}\n")
                f.write(f"# Keep this file secure and private\n")
            
            # Set secure permissions on the file
            os.chmod(env_file, 0o600)  # Read/write for owner only
            
            self.stdout.write(f"💾 Credentials saved to: {env_file}")
            self.stdout.write("🔒 File permissions set to owner-only access")
            
        except Exception as e:
            self.stderr.write(f"❌ Failed to create anonymous admin: {e}")
            return
        
        self.stdout.write("")
        self.stdout.write("🎉 Anonymous admin setup completed successfully!")
        self.stdout.write("🛡️ Your admin identity is now protected through randomized credentials")
