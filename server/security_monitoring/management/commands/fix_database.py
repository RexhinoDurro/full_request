# submissions/management/commands/fix_database.py
from django.core.management.base import BaseCommand
from django.db import connection, transaction
from django.core.management import call_command
import sys

class Command(BaseCommand):
    help = 'Fix database schema issues for submissions app'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force recreate tables if necessary',
        )

    def handle(self, *args, **options):
        self.stdout.write("🔧 Fixing database schema...")
        
        try:
            # Check current database state
            self.check_database_state()
            
            # Try to fix migrations
            self.fix_migrations(force=options['force'])
            
            # Verify the fix
            self.verify_database()
            
            self.stdout.write(
                self.style.SUCCESS("✅ Database schema fix completed successfully!")
            )
            
        except Exception as e:
            self.stderr.write(f"❌ Database fix failed: {e}")
            sys.exit(1)

    def check_database_state(self):
        """Check current database state"""
        self.stdout.write("📋 Checking database state...")
        
        with connection.cursor() as cursor:
            # Check if submissions table exists
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_name = 'submissions_submission'
            """)
            table_exists = cursor.fetchone()
            
            if table_exists:
                self.stdout.write("✅ submissions_submission table exists")
                
                # Check columns
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'submissions_submission'
                """)
                columns = [row[0] for row in cursor.fetchall()]
                
                self.stdout.write(f"📊 Columns found: {', '.join(columns)}")
                
                if 'uuid' not in columns:
                    self.stdout.write("⚠️ 'uuid' column missing!")
                    return False
                else:
                    self.stdout.write("✅ 'uuid' column exists")
                    return True
            else:
                self.stdout.write("⚠️ submissions_submission table does not exist")
                return False

    def fix_migrations(self, force=False):
        """Fix migration issues"""
        self.stdout.write("🔨 Fixing migrations...")
        
        try:
            # Reset migrations if force is True
            if force:
                self.stdout.write("⚠️ Force mode: Resetting migrations...")
                with connection.cursor() as cursor:
                    cursor.execute("""
                        DELETE FROM django_migrations 
                        WHERE app = 'submissions'
                    """)
                
                # Drop and recreate table
                cursor.execute("DROP TABLE IF EXISTS submissions_submission CASCADE")
                self.stdout.write("🗑️ Dropped existing table")
            
            # Create fresh migrations
            self.stdout.write("📝 Creating migrations...")
            call_command('makemigrations', 'submissions', '--noinput')
            
            # Apply migrations
            self.stdout.write("⚡ Applying migrations...")
            call_command('migrate', 'submissions', '--noinput')
            
            # Also ensure other apps are migrated
            call_command('migrate', '--noinput')
            
        except Exception as e:
            self.stderr.write(f"Migration fix failed: {e}")
            raise

    def verify_database(self):
        """Verify that the database is working correctly"""
        self.stdout.write("🔍 Verifying database...")
        
        try:
            from submissions.models import Submission
            from security_monitoring.models import SecurityEvent
            
            # Test basic operations
            submission_count = Submission.objects.count()
            event_count = SecurityEvent.objects.count()
            
            self.stdout.write(f"✅ Submissions table: {submission_count} records")
            self.stdout.write(f"✅ Security events table: {event_count} records")
            
            # Test model creation (dry run)
            import uuid
            test_data = {
                'name': 'Test User',
                'email': 'test@example.com',
                'phone': '+1234567890',
                'country': 'US',
                'step1': 'Test Company',
                'step8': 'Test summary'
            }
            
            # Don't actually save, just validate
            submission = Submission(**test_data)
            submission.full_clean()  # This will validate without saving
            
            self.stdout.write("✅ Model validation successful")
            
        except Exception as e:
            self.stderr.write(f"Database verification failed: {e}")
            raise