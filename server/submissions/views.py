# submissions/views.py - COMPLETE FIXED VERSION with money handling and Excel headers

import re
import hashlib
import json
import logging
from datetime import timedelta
from io import BytesIO

from django.http import HttpResponse
from django.utils import timezone
from django.core.cache import cache
from django.db import transaction
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django.views.decorators.cache import never_cache
from django.utils.decorators import method_decorator

# Excel generation (optional dependency)
try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False

from .models import Submission
from .serializers import SecureSubmissionCreateSerializer, SubmissionListSerializer, SubmissionDetailSerializer
from security_monitoring.models import SecurityEvent
from security_monitoring.utils import get_client_ip

logger = logging.getLogger('security_monitoring')

# Custom throttle classes for ultra-secure form system
class UltraSecureFormThrottle(AnonRateThrottle):
    rate = '2/min'  # Ultra-strict: 2 form submissions per minute
    
class UltraSecureAdminThrottle(UserRateThrottle):
    rate = '50/hour'  # Strict admin operations

class UltraSecureRateLimiter:
    """Built-in rate limiter using Django cache (no external dependencies)"""
    
    @staticmethod
    def is_rate_limited(key, limit, window_seconds):
        """Check if request should be rate limited using Django cache"""
        try:
            current_time = timezone.now()
            cache_key = f"rate_limit:{key}"
            
            # Get existing attempts
            attempts = cache.get(cache_key, [])
            
            # Remove old attempts outside window
            cutoff_time = current_time - timedelta(seconds=window_seconds)
            recent_attempts = [
                attempt for attempt in attempts 
                if attempt > cutoff_time.timestamp()
            ]
            
            # Check if limit exceeded
            if len(recent_attempts) >= limit:
                return True
            
            # Add current attempt
            recent_attempts.append(current_time.timestamp())
            cache.set(cache_key, recent_attempts, window_seconds)
            
            return False
            
        except Exception:
            # Fail open for availability
            return False

def log_security_event(event_type, severity, request, description, metadata=None):
    """Enhanced security event logging for form system"""
    try:
        SecurityEvent.objects.create(
            event_type=event_type,
            severity=severity,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            user=request.user if request.user.is_authenticated else None,
            description=description,
            metadata=metadata or {}
        )
        
        logger.warning(f"FORM_SECURITY: {event_type} - {description} - IP: {get_client_ip(request)}")
        
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

def parse_money_amount(step5_value):
    """Parse money amount and currency from step5 field"""
    if not step5_value:
        return None, None
    
    # Format: "amount currency" (e.g., "50000 USD")
    parts = str(step5_value).strip().split()
    if len(parts) >= 2:
        amount = parts[0]
        currency = parts[1]
        return amount, currency
    return step5_value, None

def ultra_secure_spam_detection(request, form_data):
    """Ultra-secure spam detection for form submissions"""
    client_ip = get_client_ip(request)
    
    # 1. Ultra-strict rate limiting
    if UltraSecureRateLimiter.is_rate_limited(f"form_submission:{client_ip}", 2, 3600):
        return True, "Rate limit exceeded (2 submissions per hour)"
    
    # 2. Enhanced content analysis
    all_text = ' '.join([str(form_data.get(field, '')) for field in form_data.keys()]).lower()
    
    # Ultra-strict spam indicators
    spam_indicators = {
        'critical_risk': ['spam', 'test', 'fake', 'bot', 'script'],
        'high_risk': ['urgent', 'click', 'free', 'winner', 'casino', 'viagra'],
        'suspicious_patterns': [
            r'\b\w*\d{4,}\w*\b',  # Numbers with 4+ digits (but exclude money amounts)
            r'[A-Z]{10,}',        # Too many caps
            r'(.)\1{5,}',         # Repeated characters
            r'https?://',         # URLs in form
            r'www\.',             # Web addresses
        ]
    }
    
    risk_score = 0
    
    # Check critical risk (immediate block)
    for keyword in spam_indicators['critical_risk']:
        if keyword in all_text:
            return True, f"Critical spam keyword detected: {keyword}"
    
    # Check high-risk keywords
    for keyword in spam_indicators['high_risk']:
        if keyword in all_text:
            risk_score += 15
    
    # Check suspicious patterns (but be more lenient with money amounts)
    for pattern in spam_indicators['suspicious_patterns']:
        if re.search(pattern, all_text):
            # Don't penalize money amounts heavily
            if not re.search(r'\b\d+\s+(USD|EUR|GBP|CHF|SEK|NOK|DKK|PLN|CZK|HUF)\b', all_text):
                risk_score += 10
    
    # 3. Length-based detection
    if len(all_text) > 5000:  # Very long submission
        risk_score += 20
    elif len(all_text) < 20:  # Very short submission
        risk_score += 15
    
    # 4. Field validation
    required_fields = ['name', 'email', 'phone']
    for field in required_fields:
        if not form_data.get(field, '').strip():
            risk_score += 10
    
    # 5. Email validation
    email = form_data.get('email', '')
    if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        risk_score += 20
    
    return risk_score >= 25, f"Spam detected (risk score: {risk_score})"

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([UltraSecureFormThrottle])
@csrf_exempt
@never_cache
def submit_form(request):
    """Ultra-secure form submission endpoint with money handling"""
    
    client_ip = get_client_ip(request)
    
    # Input validation
    if not request.data:
        log_security_event('SUSPICIOUS_ACTIVITY', 'MEDIUM', request, 'Empty form submission')
        return Response({
            'success': False,
            'message': 'No data provided'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Ultra-secure spam detection
        is_spam, spam_reason = ultra_secure_spam_detection(request, request.data)
        if is_spam:
            log_security_event(
                'FORM_SPAM', 'HIGH', request,
                f'Ultra-secure spam detection: {spam_reason}',
                {'form_data_length': len(str(request.data)), 'reason': spam_reason}
            )
            return Response({
                'success': False,
                'message': 'Submission blocked by security filter'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        # Ultra-secure validation
        serializer = SecureSubmissionCreateSerializer(data=request.data)
        
        if serializer.is_valid():
            # Create unique hash for duplicate detection
            data_hash = hashlib.sha256(
                json.dumps(serializer.validated_data, sort_keys=True).encode()
            ).hexdigest()
            
            # Check for duplicates (24-hour window)
            cache_key = f"submission_hash:{data_hash}"
            if cache.get(cache_key):
                log_security_event(
                    'FORM_SPAM', 'MEDIUM', request,
                    'Duplicate submission attempt within 24 hours'
                )
                return Response({
                    'success': False,
                    'message': 'Duplicate submission detected'
                }, status=status.HTTP_409_CONFLICT)
            
            # Save with ultra-secure transaction
            with transaction.atomic():
                submission = serializer.save()
                
                # Cache submission hash
                cache.set(cache_key, True, 86400)  # 24 hours
                
                # Log successful submission with money amount
                amount, currency = parse_money_amount(submission.step5)
                log_security_event(
                    'FORM_SUBMISSION', 'LOW', request,
                    f'Secure form submission: {submission.uuid}',
                    {
                        'submission_id': str(submission.uuid),
                        'investment_amount': amount,
                        'currency': currency
                    }
                )
            
            return Response({
                'success': True,
                'message': 'Form submitted successfully',
                'submission_id': str(submission.uuid)
            }, status=status.HTTP_201_CREATED)
        
        else:
            log_security_event(
                'FORM_VALIDATION_ERROR', 'LOW', request,
                'Form validation failed',
                {'error_count': len(serializer.errors)}
            )
            
            return Response({
                'success': False,
                'message': 'Please check your form data and try again',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        logger.error(f"Form submission error: {e}", exc_info=True)
        log_security_event(
            'API_ERROR', 'HIGH', request,
            'Form submission processing error'
        )
        
        return Response({
            'success': False,
            'message': 'Unable to process submission. Please try again later.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(never_cache, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class SubmissionListView(generics.ListAPIView):
    """Ultra-secure admin endpoint to list submissions"""
    serializer_class = SubmissionListSerializer
    permission_classes = [IsAdminUser]
    throttle_classes = [UltraSecureAdminThrottle]

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            log_security_event(
                'ADMIN_ACCESS', 'MEDIUM', request,
                f'Admin {request.user.username} accessed submission list',
                {'admin_user': request.user.username}
            )
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        """Ultra-secure queryset with validation"""
        queryset = Submission.objects.all()
        
        # Validate and sanitize filters
        filters = self.request.query_params
        safe_filters = {}
        
        # Ultra-strict filter validation
        allowed_filters = {
            'date_from': lambda x: x if re.match(r'^\d{4}-\d{2}-\d{2}$', x) else None,
            'date_to': lambda x: x if re.match(r'^\d{4}-\d{2}-\d{2}$', x) else None,
            'country': lambda x: x if re.match(r'^[A-Z]{2}$', x) else None,
            'search': lambda x: x[:30] if len(x) <= 30 else None,  # Limit search
            'service_type': lambda x: x[:50] if len(x) <= 50 else None,
            'issue_timeframe': lambda x: x[:50] if len(x) <= 50 else None,
            'primary_goal': lambda x: x[:50] if len(x) <= 50 else None,
            'communication_method': lambda x: x[:50] if len(x) <= 50 else None,
        }
        
        for key, validator in allowed_filters.items():
            if key in filters:
                validated_value = validator(filters[key])
                if validated_value:
                    safe_filters[key] = validated_value
        
        # Apply safe filters
        if safe_filters.get('date_from'):
            try:
                start_date = timezone.datetime.strptime(safe_filters['date_from'], '%Y-%m-%d').date()
                queryset = queryset.filter(submitted_at__date__gte=start_date)
            except ValueError:
                pass
        
        if safe_filters.get('date_to'):
            try:
                end_date = timezone.datetime.strptime(safe_filters['date_to'], '%Y-%m-%d').date()
                queryset = queryset.filter(submitted_at__date__lte=end_date)
            except ValueError:
                pass
        
        if safe_filters.get('country'):
            queryset = queryset.filter(country=safe_filters['country'])
        
        if safe_filters.get('search'):
            from django.db.models import Q
            search_term = safe_filters['search']
            queryset = queryset.filter(
                Q(name__icontains=search_term) |
                Q(email__icontains=search_term)
            )
        
        # Apply step-based filters
        if safe_filters.get('service_type'):
            queryset = queryset.filter(step2__icontains=safe_filters['service_type'])
        
        if safe_filters.get('issue_timeframe'):
            queryset = queryset.filter(step3__icontains=safe_filters['issue_timeframe'])
        
        if safe_filters.get('primary_goal'):
            queryset = queryset.filter(step5__icontains=safe_filters['primary_goal'])
        
        if safe_filters.get('communication_method'):
            queryset = queryset.filter(step7__icontains=safe_filters['communication_method'])
        
        # Log data access
        count = queryset.count()
        log_security_event(
            'DATA_ACCESS', 'LOW', self.request,
            f'Admin accessed {count} submissions',
            {'record_count': count, 'filters': safe_filters}
        )
        
        return queryset.order_by('-submitted_at')

@method_decorator(never_cache, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class SubmissionDetailView(generics.RetrieveAPIView):
    """Ultra-secure admin endpoint for submission details"""
    queryset = Submission.objects.all()
    serializer_class = SubmissionDetailSerializer
    permission_classes = [IsAdminUser]
    throttle_classes = [UltraSecureAdminThrottle]
    
    def retrieve(self, request, *args, **kwargs):
        try:
            response = super().retrieve(request, *args, **kwargs)
            
            submission_id = kwargs.get('pk')
            log_security_event(
                'SENSITIVE_DATA_ACCESS', 'HIGH', request,
                f'Admin {request.user.username} viewed submission details',
                {'submission_id': submission_id, 'admin_user': request.user.username}
            )
            
            return response
            
        except Submission.DoesNotExist:
            log_security_event(
                'SUSPICIOUS_ACTIVITY', 'MEDIUM', request,
                f'Admin attempted to access non-existent submission: {kwargs.get("pk")}'
            )
            return Response({
                'success': False,
                'message': 'Submission not found'
            }, status=status.HTTP_404_NOT_FOUND)

@api_view(['DELETE'])
@permission_classes([IsAdminUser])
@throttle_classes([UltraSecureAdminThrottle])
@csrf_exempt
@never_cache
def delete_submission(request, pk):
    """Ultra-secure admin endpoint for submission deletion"""
    
    # Rate limiting for deletions
    client_ip = get_client_ip(request)
    if UltraSecureRateLimiter.is_rate_limited(f"delete_submission:{client_ip}", 5, 3600):
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'HIGH', request,
            'Deletion rate limit exceeded'
        )
        return Response({
            'success': False,
            'message': 'Too many deletion attempts'
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)
    
    try:
        submission = Submission.objects.get(pk=pk)
        
        log_security_event(
            'DATA_DELETION', 'CRITICAL', request,
            f'Admin {request.user.username} deleted submission',
            {
                'submission_id': submission.id,
                'submission_uuid': str(submission.uuid),
                'admin_user': request.user.username,
                'submitted_at': submission.submitted_at.isoformat(),
            }
        )
        
        submission.delete()
        
        return Response({
            'success': True,
            'message': 'Submission deleted successfully'
        }, status=status.HTTP_200_OK)
        
    except Submission.DoesNotExist:
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'HIGH', request,
            f'Admin attempted to delete non-existent submission: {pk}'
        )
        return Response({
            'success': False,
            'message': 'Submission not found'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([IsAdminUser])
@throttle_classes([UltraSecureAdminThrottle])
@csrf_exempt
@never_cache
def delete_all_submissions(request):
    """Ultra-secure bulk deletion endpoint"""
    
    # Ultra-strict confirmation
    confirmation = request.data.get('confirmation')
    
    if confirmation != 'delete_permanently':
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'HIGH', request,
            'Admin attempted bulk deletion without proper confirmation'
        )
        return Response({
            'success': False,
            'message': 'Invalid confirmation. Type "delete_permanently" to confirm.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Additional IP-based rate limiting for bulk operations
    client_ip = get_client_ip(request)
    if UltraSecureRateLimiter.is_rate_limited(f"bulk_delete:{client_ip}", 1, 86400):
        log_security_event(
            'SUSPICIOUS_ACTIVITY', 'CRITICAL', request,
            'Bulk deletion rate limit exceeded (1 per day)'
        )
        return Response({
            'success': False,
            'message': 'Bulk deletion already performed today'
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)
    
    try:
        count = Submission.objects.count()
        
        log_security_event(
            'BULK_DATA_DELETION', 'CRITICAL', request,
            f'Admin {request.user.username} initiated bulk deletion of {count} submissions',
            {
                'deletion_count': count,
                'admin_user': request.user.username,
                'confirmed': True
            }
        )
        
        Submission.objects.all().delete()
        
        return Response({
            'success': True,
            'message': f'Successfully deleted {count} submissions'
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Bulk deletion error: {e}", exc_info=True)
        log_security_event(
            'API_ERROR', 'CRITICAL', request,
            f'Error in bulk deletion: {str(e)}'
        )
        return Response({
            'success': False,
            'message': 'Bulk deletion failed'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAdminUser])
@throttle_classes([UltraSecureAdminThrottle])
@csrf_exempt
def download_submissions_excel(request):
    """Generate Excel file with proper headers and money parsing"""
    
    if not EXCEL_AVAILABLE:
        return Response({
            'success': False,
            'message': 'Excel functionality not available. Install openpyxl.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    try:
        # Get filtered submissions
        filters = request.query_params
        queryset = Submission.objects.all()
        
        # Apply same filters as list view
        if filters.get('date_from'):
            try:
                start_date = timezone.datetime.strptime(filters['date_from'], '%Y-%m-%d').date()
                queryset = queryset.filter(submitted_at__date__gte=start_date)
            except ValueError:
                pass
        
        if filters.get('date_to'):
            try:
                end_date = timezone.datetime.strptime(filters['date_to'], '%Y-%m-%d').date()
                queryset = queryset.filter(submitted_at__date__lte=end_date)
            except ValueError:
                pass
        
        if filters.get('country'):
            queryset = queryset.filter(country=filters['country'])
        
        # Limit for security (max 1000 records)
        submissions = queryset.order_by('-submitted_at')[:1000]
        
        # Create Excel workbook
        wb = Workbook()
        ws = wb.active
        ws.title = "Form Submissions"
        
        # Define proper column headers
        headers = [
            'ID',
            'UUID', 
            'Name',
            'Email',
            'Phone',
            'Country',
            'Company Name',
            'Service Type',
            'Issue Timeframe', 
            'Company Acknowledgment',
            'Investment Amount',
            'Currency',
            'How Heard About Us',
            'Preferred Communication',
            'Case Summary',
            'Submitted At',
            'Data Classification',
            'Anonymized'
        ]
        
        # Style headers
        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
        
        # Add headers as the very first row
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal="center")
        
        # Add data rows starting from row 2
        for row, submission in enumerate(submissions, 2):
            try:
                # Parse money amount and currency from step5
                amount, currency = parse_money_amount(submission.step5)
                
                ws.cell(row=row, column=1, value=submission.id)
                ws.cell(row=row, column=2, value=str(submission.uuid))
                ws.cell(row=row, column=3, value=str(submission.name) if not submission.anonymized else "ANONYMIZED")
                ws.cell(row=row, column=4, value=str(submission.email) if not submission.anonymized else "ANONYMIZED")
                ws.cell(row=row, column=5, value=str(submission.phone) if not submission.anonymized else "ANONYMIZED")
                ws.cell(row=row, column=6, value=submission.country)
                ws.cell(row=row, column=7, value=str(submission.step1) if submission.step1 else "")
                ws.cell(row=row, column=8, value=str(submission.step2) if submission.step2 else "")
                ws.cell(row=row, column=9, value=str(submission.step3) if submission.step3 else "")
                ws.cell(row=row, column=10, value=str(submission.step4) if submission.step4 else "")
                ws.cell(row=row, column=11, value=amount if amount else "")
                ws.cell(row=row, column=12, value=currency if currency else "")
                ws.cell(row=row, column=13, value=str(submission.step6) if submission.step6 else "")
                ws.cell(row=row, column=14, value=str(submission.step7) if submission.step7 else "")
                ws.cell(row=row, column=15, value=str(submission.step8) if submission.step8 else "")
                ws.cell(row=row, column=16, value=submission.submitted_at.strftime('%Y-%m-%d %H:%M:%S'))
                ws.cell(row=row, column=17, value=submission.data_classification)
                ws.cell(row=row, column=18, value="Yes" if submission.anonymized else "No")
            except Exception as e:
                # Skip problematic rows but continue
                logger.error(f"Error processing submission {submission.id}: {e}")
                continue
        
        # Auto-adjust column widths
        for column in ws.columns:
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)  # Max width 50
            ws.column_dimensions[column_letter].width = adjusted_width
        
        # Save to memory
        output = BytesIO()
        wb.save(output)
        output.seek(0)
        
        # Log the export
        log_security_event(
            'DATA_EXPORT', 'HIGH', request,
            f'Admin {request.user.username} exported {len(submissions)} submissions to Excel',
            {
                'export_count': len(submissions),
                'admin_user': request.user.username,
                'filters_applied': dict(filters)
            }
        )
        
        # Generate filename with timestamp
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        filename = f'form_submissions_{timestamp}.xlsx'
        
        # Return Excel file
        response = HttpResponse(
            output.getvalue(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        response['Content-Length'] = len(output.getvalue())
        
        return response
        
    except Exception as e:
        logger.error(f"Excel export error: {e}", exc_info=True)
        log_security_event(
            'API_ERROR', 'HIGH', request,
            f'Excel export failed: {str(e)}'
        )
        return Response({
            'success': False,
            'message': 'Failed to generate Excel file'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAdminUser])
@csrf_exempt
def get_filter_options(request):
    """Get available filter options including investment amounts"""
    try:
        # Get unique values for filters from actual submissions
        submissions = Submission.objects.all()
        
        # Extract unique countries
        countries = list(submissions.values_list('country', flat=True).distinct().order_by('country'))
        country_options = [{'code': country, 'display': country} for country in countries if country]
        
        # Extract service types from step2
        service_types = []
        for submission in submissions:
            if submission.step2:
                service_type = str(submission.step2).strip()
                if service_type and service_type not in service_types:
                    service_types.append(service_type)
        
        # Extract issue timeframes from step3
        issue_timeframes = []
        for submission in submissions:
            if submission.step3:
                timeframe = str(submission.step3).strip()
                if timeframe and timeframe not in issue_timeframes:
                    issue_timeframes.append(timeframe)
        
        # Extract acknowledgments from step4
        acknowledgments = []
        for submission in submissions:
            if submission.step4:
                ack = str(submission.step4).strip()
                if ack and ack not in acknowledgments:
                    acknowledgments.append(ack)
        
        # Extract investment amounts from step5 (now money amounts)
        investment_amounts = []
        for submission in submissions:
            if submission.step5:
                amount, currency = parse_money_amount(submission.step5)
                if amount and currency:
                    investment_display = f"{amount} {currency}"
                    if investment_display not in investment_amounts:
                        investment_amounts.append(investment_display)
        
        # Extract heard abouts from step6
        heard_abouts = []
        for submission in submissions:
            if submission.step6:
                heard = str(submission.step6).strip()
                if heard and heard not in heard_abouts:
                    heard_abouts.append(heard)
        
        # Extract communication methods from step7
        communication_methods = []
        for submission in submissions:
            if submission.step7:
                method = str(submission.step7).strip()
                if method and method not in communication_methods:
                    communication_methods.append(method)
        
        return Response({
            'success': True,
            'service_types': sorted(service_types[:20]),
            'issue_timeframes': sorted(issue_timeframes[:20]),
            'acknowledgments': sorted(acknowledgments[:20]),
            'investment_amounts': sorted(investment_amounts[:20]),
            'heard_abouts': sorted(heard_abouts[:20]),
            'communication_methods': sorted(communication_methods[:20]),
            'countries': country_options
        })
        
    except Exception as e:
        logger.error(f"Filter options error: {e}")
        return Response({
            'success': False, 
            'message': 'Failed to load filter options'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAdminUser])
@csrf_exempt
def submission_stats(request):
    """Get comprehensive submission statistics with money analysis"""
    try:
        from django.db.models import Count
        from datetime import datetime, timedelta
        
        # Get filters from request
        filters = request.query_params
        queryset = Submission.objects.all()
        
        # Apply filters to statistics
        if filters.get('date_from'):
            try:
                start_date = timezone.datetime.strptime(filters['date_from'], '%Y-%m-%d').date()
                queryset = queryset.filter(submitted_at__date__gte=start_date)
            except ValueError:
                pass
        
        if filters.get('date_to'):
            try:
                end_date = timezone.datetime.strptime(filters['date_to'], '%Y-%m-%d').date()
                queryset = queryset.filter(submitted_at__date__lte=end_date)
            except ValueError:
                pass
        
        # Apply preset date filters
        now = timezone.now()
        if filters.get('date_preset'):
            preset = filters['date_preset']
            if preset == 'today':
                queryset = queryset.filter(submitted_at__date=now.date())
            elif preset == '1_week':
                one_week_ago = now - timedelta(days=7)
                queryset = queryset.filter(submitted_at__gte=one_week_ago)
            elif preset == '2_weeks':
                two_weeks_ago = now - timedelta(days=14)
                queryset = queryset.filter(submitted_at__gte=two_weeks_ago)
            elif preset == '30_days':
                thirty_days_ago = now - timedelta(days=30)
                queryset = queryset.filter(submitted_at__gte=thirty_days_ago)
        
        # Basic stats
        total_submissions = queryset.count()
        
        # Service type breakdown from step2
        service_type_breakdown = {}
        for submission in queryset:
            if submission.step2:
                service_type = str(submission.step2).strip()
                if service_type:
                    service_type_breakdown[service_type] = service_type_breakdown.get(service_type, 0) + 1
        
        # Country breakdown
        country_breakdown = {}
        country_counts = queryset.values('country').annotate(count=Count('country')).order_by('-count')
        for item in country_counts:
            if item['country']:
                country_breakdown[item['country']] = item['count']
        
        # Issue timeframe breakdown from step3
        issue_timeframe_breakdown = {}
        for submission in queryset:
            if submission.step3:
                timeframe = str(submission.step3).strip()
                if timeframe:
                    issue_timeframe_breakdown[timeframe] = issue_timeframe_breakdown.get(timeframe, 0) + 1
        
        # Investment amount breakdown by currency from step5
        currency_breakdown = {}
        total_investment = {}
        investment_ranges = {
            'Under 1K': 0,
            '1K-10K': 0,
            '10K-50K': 0,
            '50K-100K': 0,
            '100K-500K': 0,
            '500K+': 0
        }
        
        for submission in queryset:
            if submission.step5:
                amount, currency = parse_money_amount(submission.step5)
                if amount and currency:
                    # Count by currency
                    currency_breakdown[currency] = currency_breakdown.get(currency, 0) + 1
                    
                    # Sum amounts by currency
                    try:
                        amount_float = float(amount.replace(',', ''))
                        total_investment[currency] = total_investment.get(currency, 0) + amount_float
                        
                        # Categorize by investment range
                        if amount_float < 1000:
                            investment_ranges['Under 1K'] += 1
                        elif amount_float < 10000:
                            investment_ranges['1K-10K'] += 1
                        elif amount_float < 50000:
                            investment_ranges['10K-50K'] += 1
                        elif amount_float < 100000:
                            investment_ranges['50K-100K'] += 1
                        elif amount_float < 500000:
                            investment_ranges['100K-500K'] += 1
                        else:
                            investment_ranges['500K+'] += 1
                            
                    except (ValueError, AttributeError):
                        pass
        
        # Daily submissions for charts
        daily_submissions = []
        
        # Determine date range for daily stats
        if filters.get('date_from') and filters.get('date_to'):
            start_date = timezone.datetime.strptime(filters['date_from'], '%Y-%m-%d').date()
            end_date = timezone.datetime.strptime(filters['date_to'], '%Y-%m-%d').date()
        else:
            # Default to last 30 days
            end_date = now.date()
            start_date = end_date - timedelta(days=30)
        
        # Generate daily stats
        current_date = start_date
        while current_date <= end_date:
            day_count = queryset.filter(submitted_at__date=current_date).count()
            daily_submissions.append({
                'date': current_date.isoformat(),
                'count': day_count
            })
            current_date += timedelta(days=1)
        
        # Date range info
        date_range = {
            'from': start_date.isoformat(),
            'to': end_date.isoformat(),
            'preset': filters.get('date_preset', '')
        }
        
        # Calculate additional investment statistics
        avg_investment_by_currency = {}
        for currency, total in total_investment.items():
            count = currency_breakdown.get(currency, 1)
            avg_investment_by_currency[currency] = round(total / count, 2)
        
        return Response({
            'success': True,
            'total_submissions': total_submissions,
            'service_type_breakdown': service_type_breakdown,
            'country_breakdown': country_breakdown,
            'issue_timeframe_breakdown': issue_timeframe_breakdown,
            'currency_breakdown': currency_breakdown,
            'total_investment': total_investment,
            'avg_investment_by_currency': avg_investment_by_currency,
            'investment_ranges': investment_ranges,
            'daily_submissions': daily_submissions,
            'date_range': date_range
        })
        
    except Exception as e:
        logger.error(f"Stats error: {e}", exc_info=True)
        return Response({
            'success': False, 
            'message': 'Failed to load statistics'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)