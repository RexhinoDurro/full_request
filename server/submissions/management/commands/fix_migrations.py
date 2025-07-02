# server/submissions/management/commands/fix_migrations.py
from django.core.management.base import BaseCommand
from django.db import connection, transaction
from django.core.management import call_command
import sys

class Command(BaseCommand):
    help = 'Fix Django migration issues with existing database tables'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force fix even if it might cause data loss',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes',
        )

    def handle(self, *args, **options):
        self.stdout.write("🔧 Analyzing database migration state...")
        
        try:
            analysis = self.analyze_database_state()
            self.display_analysis(analysis)
            
            if options['dry_run']:
                self.stdout.write("🔍 DRY RUN - No changes will be made")
                self.show_recommended_actions(analysis)
                return
            
            # Apply fixes based on analysis
            self.apply_fixes(analysis, force=options['force'])
            
        except Exception as e:
            self.stderr.write(f"❌ Error during migration fix: {e}")
            sys.exit(1)

    def analyze_database_state(self):
        """Analyze current database and migration state"""
        analysis = {
            'tables_exist': {},
            'migrations_recorded': {},
            'migration_table_exists': False,
            'issues_found': [],
            'recommended_actions': []
        }
        
        with connection.cursor() as cursor:
            # Check if django_migrations table exists
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'django_migrations'
                );
            """)
            analysis['migration_table_exists'] = cursor.fetchone()[0]
            
            # Check critical tables
            critical_tables = [
                'submissions_submission',
                'security_monitoring_securityevent',
                'auth_user',
                'django_content_type',
            ]
            
            for table in critical_tables:
                cursor.execute(f"""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = '{table}'
                    );
                """)
                analysis['tables_exist'][table] = cursor.fetchone()[0]
            
            # Check migration records if migration table exists
            if analysis['migration_table_exists']:
                critical_migrations = [
                    ('submissions', '0001_initial'),
                    ('security_monitoring', '0001_initial'),
                    ('auth', '0001_initial'),
                    ('contenttypes', '0001_initial'),
                ]
                
                for app, migration in critical_migrations:
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM django_migrations 
                            WHERE app = %s AND name = %s
                        );
                    """, [app, migration])
                    analysis['migrations_recorded'][f"{app}.{migration}"] = cursor.fetchone()[0]
        
        # Analyze issues
        self.detect_issues(analysis)
        
        return analysis

    def detect_issues(self, analysis):
        """Detect migration issues"""
        issues = analysis['issues_found']
        recommendations = analysis['recommended_actions']
        
        # Issue 1: Tables exist but migrations not recorded
        if analysis['tables_exist']['submissions_submission']:
            if not analysis['migration_table_exists']:
                issues.append("submissions_submission table exists but django_migrations table missing")
                recommendations.append("Create django_migrations table and fake initial migrations")
            elif not analysis['migrations_recorded'].get('submissions.0001_initial', False):
                issues.append("submissions_submission table exists but initial migration not recorded")
                recommendations.append("Fake the submissions initial migration")
        
        # Issue 2: Migration table exists but some migrations missing
        if analysis['migration_table_exists']:
            for migration, recorded in analysis['migrations_recorded'].items():
                if not recorded:
                    app_name = migration.split('.')[0]
                    table_name = f"{app_name}_" + migration.split('.')[1].replace('0001_initial', '')
                    if app_name == 'submissions':
                        table_name = 'submissions_submission'
                    elif app_name == 'security_monitoring':
                        table_name = 'security_monitoring_securityevent'
                    
                    if analysis['tables_exist'].get(table_name, False):
                        issues.append(f"Migration {migration} not recorded but table exists")
                        recommendations.append(f"Fake migration {migration}")
        
        # Issue 3: No issues found
        if not issues:
            issues.append("No migration issues detected")
            recommendations.append("Run normal Django migrations")

    def display_analysis(self, analysis):
        """Display the analysis results"""
        self.stdout.write("\n📊 DATABASE ANALYSIS RESULTS:")
        self.stdout.write("=" * 50)
        
        # Tables status
        self.stdout.write("\n📋 Table Status:")
        for table, exists in analysis['tables_exist'].items():
            status = "✅ EXISTS" if exists else "❌ MISSING"
            self.stdout.write(f"  {table}: {status}")
        
        # Migration status
        self.stdout.write(f"\n📋 Django Migrations Table: {'✅ EXISTS' if analysis['migration_table_exists'] else '❌ MISSING'}")
        
        if analysis['migration_table_exists']:
            self.stdout.write("\n📋 Migration Records:")
            for migration, recorded in analysis['migrations_recorded'].items():
                status = "✅ RECORDED" if recorded else "❌ MISSING"
                self.stdout.write(f"  {migration}: {status}")
        
        # Issues
        self.stdout.write(f"\n⚠️  Issues Found ({len(analysis['issues_found'])}):")
        for issue in analysis['issues_found']:
            self.stdout.write(f"  - {issue}")

    def show_recommended_actions(self, analysis):
        """Show recommended actions"""
        self.stdout.write(f"\n🔧 Recommended Actions ({len(analysis['recommended_actions'])}):")
        for action in analysis['recommended_actions']:
            self.stdout.write(f"  - {action}")

    def apply_fixes(self, analysis, force=False):
        """Apply fixes based on analysis"""
        self.stdout.write("\n🔧 Applying fixes...")
        
        if not analysis['issues_found'] or analysis['issues_found'] == ["No migration issues detected"]:
            self.stdout.write("✅ No fixes needed - running normal migration")
            call_command('migrate', verbosity=1)
            return
        
        # Fix 1: Create django_migrations table if missing
        if not analysis['migration_table_exists']:
            self.stdout.write("🔧 Creating django_migrations table...")
            with connection.cursor() as cursor:
                cursor.execute('''
                    CREATE TABLE django_migrations (
                        id SERIAL PRIMARY KEY,
                        app VARCHAR(255) NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        applied TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                    );
                ''')
            self.stdout.write("✅ django_migrations table created")
        
        # Fix 2: Fake initial migrations for existing tables
        if analysis['tables_exist']['submissions_submission'] and not analysis['migrations_recorded'].get('submissions.0001_initial', False):
            self.stdout.write("🔧 Faking submissions initial migration...")
            try:
                call_command('migrate', 'submissions', '0001', '--fake', verbosity=0)
                self.stdout.write("✅ Faked submissions initial migration")
            except Exception as e:
                self.stdout.write(f"⚠️ Could not fake migration: {e}")
        
        # Fix 3: Run remaining migrations
        self.stdout.write("🔧 Running remaining migrations...")
        try:
            call_command('migrate', verbosity=1)
            self.stdout.write("✅ All migrations completed")
        except Exception as e:
            if not force:
                self.stderr.write(f"❌ Migration failed: {e}")
                self.stderr.write("Use --force to attempt more aggressive fixes")
                return
            
            self.stdout.write("⚠️ Normal migration failed, trying fake-initial...")
            try:
                call_command('migrate', '--fake-initial', verbosity=1)
                self.stdout.write("✅ Fake-initial migration completed")
            except Exception as e2:
                self.stderr.write(f"❌ Fake-initial also failed: {e2}")
                return
        
        # Verify fixes
        self.stdout.write("\n🔍 Verifying fixes...")
        try:
            from submissions.models import Submission
            from security_monitoring.models import SecurityEvent
            
            submission_count = Submission.objects.count()
            event_count = SecurityEvent.objects.count()
            
            self.stdout.write(f"✅ Submissions table accessible: {submission_count} records")
            self.stdout.write(f"✅ Security events table accessible: {event_count} records")
            self.stdout.write("🎉 Migration fixes completed successfully!")
            
        except Exception as e:
            self.stderr.write(f"⚠️ Verification failed: {e}")
            self.stderr.write("Database may need manual intervention")