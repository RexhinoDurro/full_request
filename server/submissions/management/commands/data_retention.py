# submissions/management/commands/data_retention.py - Data retention command
from django.core.management.base import BaseCommand
from django.utils import timezone
from submissions.models import EncryptedSubmission, DataRetentionLog
from django.contrib.auth.models import User

class Command(BaseCommand):
    help = 'Process data retention policies'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be processed without making changes',
        )
        parser.add_argument(
            '--action',
            choices=['anonymize', 'delete'],
            default='anonymize',
            help='Action to take on expired data',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        action = options['action']
        
        # Get system user for logging
        system_user, _ = User.objects.get_or_create(
            username='system',
            defaults={'email': 'system@formsite.com', 'is_active': False}
        )
        
        # Find submissions that need retention action
        expired_submissions = EncryptedSubmission.objects.needs_retention_action()
        
        self.stdout.write(
            f"Found {expired_submissions.count()} submissions requiring retention action"
        )
        
        if dry_run:
            for submission in expired_submissions:
                self.stdout.write(
                    f"Would {action}: {submission.uuid} (submitted: {submission.submitted_at})"
                )
            return
        
        # Process each submission
        processed_count = 0
        for submission in expired_submissions:
            try:
                if action == 'anonymize':
                    submission.anonymize()
                    DataRetentionLog.objects.create(
                        action_type='ANONYMIZE',
                        submission_uuid=submission.uuid,
                        performed_by=system_user,
                        reason='Automatic data retention policy',
                        metadata={'original_submission_date': submission.submitted_at.isoformat()}
                    )
                elif action == 'delete':
                    DataRetentionLog.objects.create(
                        action_type='DELETE',
                        submission_uuid=submission.uuid,
                        performed_by=system_user,
                        reason='Automatic data retention policy',
                        metadata={'submission_data_summary': submission.short_summary}
                    )
                    submission.delete()
                
                processed_count += 1
                
            except Exception as e:
                self.stderr.write(f"Error processing {submission.uuid}: {e}")
        
        self.stdout.write(
            self.style.SUCCESS(f"Successfully processed {processed_count} submissions")
        )