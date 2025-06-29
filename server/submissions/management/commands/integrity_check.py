# submissions/management/commands/integrity_check.py - Data integrity check
from django.core.management.base import BaseCommand
from submissions.models import EncryptedSubmission
from security_monitoring.models import SecurityEvent

class Command(BaseCommand):
    help = 'Check data integrity of all submissions'

    def handle(self, *args, **options):
        self.stdout.write("Starting integrity check...")
        
        failed_checks = EncryptedSubmission.objects.integrity_check()
        
        if failed_checks:
            self.stderr.write(
                f"CRITICAL: {len(failed_checks)} submissions failed integrity check!"
            )
            
            # Log security event
            SecurityEvent.objects.create(
                event_type='DATA_INTEGRITY_FAILURE',
                severity='CRITICAL',
                ip_address='127.0.0.1',
                description=f'Data integrity check failed for {len(failed_checks)} submissions',
                metadata={'failed_submissions': failed_checks}
            )
            
            for uuid in failed_checks:
                self.stderr.write(f"Failed: {uuid}")
        else:
            self.stdout.write(
                self.style.SUCCESS("All submissions passed integrity check")
            )