# security_monitoring/management/commands/cleanup_events.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from security_monitoring.models import SecurityEvent

class Command(BaseCommand):
    help = 'Clean up old security events'

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, default=365, help='Keep events newer than this many days')
        parser.add_argument('--dry-run', action='store_true', help='Show what would be deleted without actually deleting')

    def handle(self, *args, **options):
        days = options['days']
        cutoff_date = timezone.now() - timedelta(days=days)
        
        old_events = SecurityEvent.objects.filter(timestamp__lt=cutoff_date)
        count = old_events.count()
        
        if options['dry_run']:
            self.stdout.write(f"Would delete {count} security events older than {days} days")
            return
        
        if count > 0:
            old_events.delete()
            self.stdout.write(f"Deleted {count} security events older than {days} days")
        else:
            self.stdout.write("No old security events to delete")
