# security_monitoring/management/commands/security_report.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from security_monitoring.models import SecurityEvent
import json

class Command(BaseCommand):
    help = 'Generate security report'

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, default=7, help='Number of days to report on')
        parser.add_argument('--format', choices=['json', 'text'], default='text', help='Output format')

    def handle(self, *args, **options):
        days = options['days']
        start_date = timezone.now() - timedelta(days=days)
        
        events = SecurityEvent.objects.filter(timestamp__gte=start_date)
        
        # Generate report
        report = {
            'period': f"Last {days} days",
            'total_events': events.count(),
            'by_severity': {},
            'by_type': {},
            'top_ips': {},
            'unresolved_critical': events.filter(severity='CRITICAL', resolved=False).count()
        }
        
        # Group by severity
        for severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            report['by_severity'][severity] = events.filter(severity=severity).count()
        
        # Group by type
        for event_type, _ in SecurityEvent.EVENT_TYPES:
            count = events.filter(event_type=event_type).count()
            if count > 0:
                report['by_type'][event_type] = count
        
        # Top problematic IPs
        ip_counts = {}
        for event in events:
            ip_counts[event.ip_address] = ip_counts.get(event.ip_address, 0) + 1
        
        report['top_ips'] = dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        
        if options['format'] == 'json':
            self.stdout.write(json.dumps(report, indent=2))
        else:
            self.stdout.write(f"Security Report - {report['period']}")
            self.stdout.write(f"Total Events: {report['total_events']}")
            self.stdout.write(f"Unresolved Critical: {report['unresolved_critical']}")
            self.stdout.write("\nBy Severity:")
            for severity, count in report['by_severity'].items():
                self.stdout.write(f"  {severity}: {count}")