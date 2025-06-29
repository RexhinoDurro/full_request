# security_monitoring/management/commands/threat_update.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from security_monitoring.models import ThreatIntelligence
import requests
import json

class Command(BaseCommand):
    help = 'Update threat intelligence feeds'

    def add_arguments(self, parser):
        parser.add_argument('--source', help='Specific threat feed source to update')

    def handle(self, *args, **options):
        self.stdout.write("Updating threat intelligence feeds...")
        
        # Example threat feeds - replace with actual feeds in production
        feeds = {
            'malicious_ips': 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
            'tor_exits': 'https://check.torproject.org/torbulkexitlist',
        }
        
        for feed_name, feed_url in feeds.items():
            if options['source'] and options['source'] != feed_name:
                continue
                
            try:
                self.stdout.write(f"Updating {feed_name}...")
                response = requests.get(feed_url, timeout=30)
                response.raise_for_status()
                
                # Process malicious IPs
                if feed_name == 'malicious_ips':
                    lines = response.text.strip().split('\n')
                    updated_count = 0
                    
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Extract IP from line (format may vary)
                            ip = line.split()[0] if ' ' in line else line
                            
                            # Validate IP format
                            import ipaddress
                            try:
                                ipaddress.ip_address(ip)
                                
                                # Update or create threat intelligence entry
                                obj, created = ThreatIntelligence.objects.update_or_create(
                                    threat_type='IP',
                                    indicator=ip,
                                    defaults={
                                        'description': f'Malicious IP from {feed_name}',
                                        'confidence': 80,
                                        'source': feed_name,
                                        'is_active': True,
                                    }
                                )
                                if created:
                                    updated_count += 1
                                    
                            except ValueError:
                                continue
                    
                    self.stdout.write(f"Updated {updated_count} malicious IPs")
                
            except Exception as e:
                self.stderr.write(f"Failed to update {feed_name}: {e}")
        
        self.stdout.write("Threat intelligence update completed")
