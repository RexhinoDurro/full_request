# server/submissions/management/commands/reset_database.py
from django.core.management.base import BaseCommand
from django.db import connection
from django.core.management import call_command

class Command(BaseCommand):
    help = 'Reset database by dropping all tables and recreating from migrations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Confirm that you want to delete ALL data',
        )

    def handle(self, *args, **options):
        if not options['confirm']:
            self.stdout.write(
                self.style.ERROR(
                    'This command will DELETE ALL DATA in the database!\n'
                    'Run with --confirm flag if you are sure.\n'
                    'Example: python manage.py reset_database --confirm'
                )
            )
            return

        self.stdout.write("🔥 RESETTING DATABASE - ALL DATA WILL BE LOST!")
        
        try:
            with connection.cursor() as cursor:
                # Get all table names
                cursor.execute("""
                    SELECT tablename FROM pg_tables 
                    WHERE schemaname = 'public';
                """)
                tables = cursor.fetchall()
                
                self.stdout.write(f"📋 Found {len(tables)} tables to drop")
                
                # Drop all tables
                for table in tables:
                    table_name = table[0]
                    try:
                        cursor.execute(f'DROP TABLE IF EXISTS "{table_name}" CASCADE;')
                        self.stdout.write(f"🗑️ Dropped table: {table_name}")
                    except Exception as e:
                        self.stdout.write(f"⚠️ Could not drop {table_name}: {e}")
                
                # Also drop sequences and other objects
                cursor.execute("""
                    DROP SCHEMA public CASCADE;
                    CREATE SCHEMA public;
                    GRANT ALL ON SCHEMA public TO postgres;
                    GRANT ALL ON SCHEMA public TO public;
                """)
                
                self.stdout.write("✅ Database schema reset complete")
                
        except Exception as e:
            self.stderr.write(f"❌ Error resetting database: {e}")
            return
        
        # Recreate migrations and apply them
        try:
            self.stdout.write("📝 Creating fresh migrations...")
            call_command('makemigrations')
            
            self.stdout.write("⚡ Applying migrations...")
            call_command('migrate')
            
            self.stdout.write("✅ Fresh database created successfully!")
            
        except Exception as e:
            self.stderr.write(f"⚠️ Error in post-reset setup: {e}")
            self.stdout.write("You may need to run migrations manually")
        
        self.stdout.write(
            self.style.SUCCESS(
                "\n🎉 Database reset complete!\n"
                "- All old data has been deleted\n" 
                "- Fresh migrations applied\n"
                "- Ready for new deployment\n"
            )
        )