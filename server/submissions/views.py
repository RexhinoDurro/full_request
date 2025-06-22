from django.http import HttpResponse
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Q, Count
import io

from .models import Submission
from .serializers import (
    SubmissionCreateSerializer, 
    SubmissionListSerializer, 
    SubmissionDetailSerializer
)

def get_client_ip(request):
    """Get the client's IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

@api_view(['POST'])
@permission_classes([AllowAny])
def submit_form(request):
    """Public endpoint for form submission from client website"""
    serializer = SubmissionCreateSerializer(data=request.data)
    
    if serializer.is_valid():
        submission = serializer.save(ip_address=get_client_ip(request))
        
        return Response({
            'success': True,
            'message': 'Form submitted successfully',
            'submission_id': submission.id
        }, status=status.HTTP_201_CREATED)
    
    return Response({
        'success': False,
        'message': 'Form submission failed',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

class SubmissionListView(generics.ListAPIView):
    """Admin endpoint to list all submissions with filtering"""
    serializer_class = SubmissionListSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Submission.objects.all()
        
        # Apply filters
        filters = self.request.query_params
        
        # Date range filtering
        date_from = filters.get('date_from')
        date_to = filters.get('date_to')
        date_preset = filters.get('date_preset')
        
        if date_preset:
            now = timezone.now()
            if date_preset == 'today':
                start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
                queryset = queryset.filter(submitted_at__gte=start_date)
            elif date_preset == '1_week':
                start_date = now - timedelta(days=7)
                queryset = queryset.filter(submitted_at__gte=start_date)
            elif date_preset == '2_weeks':
                start_date = now - timedelta(days=14)
                queryset = queryset.filter(submitted_at__gte=start_date)
            elif date_preset == '30_days':
                start_date = now - timedelta(days=30)
                queryset = queryset.filter(submitted_at__gte=start_date)
        elif date_from and date_to:
            queryset = queryset.filter(
                submitted_at__date__gte=date_from,
                submitted_at__date__lte=date_to
            )
        elif date_from:
            queryset = queryset.filter(submitted_at__date__gte=date_from)
        elif date_to:
            queryset = queryset.filter(submitted_at__date__lte=date_to)
        
        # Field-specific filters
        if filters.get('service_type'):
            queryset = queryset.filter(step2__icontains=filters.get('service_type'))
        
        if filters.get('issue_timeframe'):
            queryset = queryset.filter(step3__icontains=filters.get('issue_timeframe'))
        
        if filters.get('acknowledgment'):
            queryset = queryset.filter(step4__icontains=filters.get('acknowledgment'))
        
        if filters.get('primary_goal'):
            queryset = queryset.filter(step5__icontains=filters.get('primary_goal'))
        
        if filters.get('heard_about'):
            queryset = queryset.filter(step6__icontains=filters.get('heard_about'))
        
        if filters.get('communication_method'):
            queryset = queryset.filter(step7__icontains=filters.get('communication_method'))
        
        if filters.get('country'):
            queryset = queryset.filter(country__icontains=filters.get('country'))
        
        if filters.get('search'):
            search_term = filters.get('search')
            queryset = queryset.filter(
                Q(name__icontains=search_term) |
                Q(email__icontains=search_term) |
                Q(phone__icontains=search_term) |
                Q(step1__icontains=search_term) |
                Q(step8__icontains=search_term)
            )
        
        return queryset.order_by('-submitted_at')

class SubmissionDetailView(generics.RetrieveAPIView):
    """Admin endpoint to view detailed submission"""
    queryset = Submission.objects.all()
    serializer_class = SubmissionDetailSerializer
    permission_classes = [IsAuthenticated]

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_submission(request, pk):
    """Admin endpoint to delete individual submission"""
    try:
        submission = Submission.objects.get(pk=pk)
        submission.delete()
        return Response({
            'success': True,
            'message': 'Submission deleted successfully'
        }, status=status.HTTP_200_OK)
    except Submission.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Submission not found'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_all_submissions(request):
    """Admin endpoint to delete all submissions (requires confirmation)"""
    confirmation = request.data.get('confirmation')
    
    if confirmation != 'delete_permanently':
        return Response({
            'success': False,
            'message': 'Invalid confirmation. Type "delete_permanently" to confirm.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    count = Submission.objects.count()
    Submission.objects.all().delete()
    
    return Response({
        'success': True,
        'message': f'Successfully deleted {count} submissions'
    }, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_filter_options(request):
    """Get all unique filter options for dropdowns"""
    
    # Helper function to get clean, non-empty unique values
    def get_unique_values(field_name):
        values = Submission.objects.exclude(**{f'{field_name}__isnull': True}) \
                                 .exclude(**{f'{field_name}__exact': ''}) \
                                 .values_list(field_name, flat=True) \
                                 .distinct()
        # Filter out None values and strip whitespace, then sort
        clean_values = sorted([v.strip() for v in values if v and v.strip()])
        return list(set(clean_values))  # Remove duplicates and convert back to list
    
    # Country mapping for better display
    country_codes = {
        'US': 'United States 🇺🇸',
        'GB': 'United Kingdom 🇬🇧', 
        'CA': 'Canada 🇨🇦',
        'AU': 'Australia 🇦🇺',
        'DE': 'Germany 🇩🇪',
        'FR': 'France 🇫🇷',
        'JP': 'Japan 🇯🇵',
        'IN': 'India 🇮🇳',
        'AL': 'Albania 🇦🇱',
        'IT': 'Italy 🇮🇹',
        'ES': 'Spain 🇪🇸',
        'NL': 'Netherlands 🇳🇱',
        'BR': 'Brazil 🇧🇷',
        'MX': 'Mexico 🇲🇽',
        'CN': 'China 🇨🇳',
        'RU': 'Russia 🇷🇺',
        'KR': 'South Korea 🇰🇷',
        'SG': 'Singapore 🇸🇬',
        'CH': 'Switzerland 🇨🇭',
        'SE': 'Sweden 🇸🇪',
        'NO': 'Norway 🇳🇴',
        'DK': 'Denmark 🇩🇰',
        'FI': 'Finland 🇫🇮',
        'BE': 'Belgium 🇧🇪',
        'AT': 'Austria 🇦🇹',
        'IE': 'Ireland 🇮🇪',
        'PT': 'Portugal 🇵🇹',
        'PL': 'Poland 🇵🇱',
        'GR': 'Greece 🇬🇷',
        'CZ': 'Czech Republic 🇨🇿',
        'HU': 'Hungary 🇭🇺',
        'RO': 'Romania 🇷🇴',
        'BG': 'Bulgaria 🇧🇬',
        'HR': 'Croatia 🇭🇷',
        'SK': 'Slovakia 🇸🇰',
        'SI': 'Slovenia 🇸🇮',
        'EE': 'Estonia 🇪🇪',
        'LV': 'Latvia 🇱🇻',
        'LT': 'Lithuania 🇱🇹',
        'MT': 'Malta 🇲🇹',
        'CY': 'Cyprus 🇨🇾',
        'LU': 'Luxembourg 🇱🇺',
    }
    
    # Get unique countries and map them to display names
    country_codes_raw = get_unique_values('country')
    countries_display = []
    for code in country_codes_raw:
        display_name = country_codes.get(code, f'{code} 🌍')
        countries_display.append({'code': code, 'display': display_name})
    
    return Response({
        'service_types': get_unique_values('step2'),
        'issue_timeframes': get_unique_values('step3'),
        'acknowledgments': get_unique_values('step4'),
        'primary_goals': get_unique_values('step5'),
        'heard_abouts': get_unique_values('step6'),
        'communication_methods': get_unique_values('step7'),
        'countries': countries_display,
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_submissions_excel(request):
    """Admin endpoint to download submissions as Excel file"""
    
    # Apply same filtering logic as list view
    queryset = Submission.objects.all()
    filters = request.GET
    
    # Apply filters (same logic as SubmissionListView)
    date_from = filters.get('date_from')
    date_to = filters.get('date_to')
    date_preset = filters.get('date_preset')
    
    if date_preset:
        now = timezone.now()
        if date_preset == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            queryset = queryset.filter(submitted_at__gte=start_date)
        elif date_preset == '1_week':
            start_date = now - timedelta(days=7)
            queryset = queryset.filter(submitted_at__gte=start_date)
        elif date_preset == '2_weeks':
            start_date = now - timedelta(days=14)
            queryset = queryset.filter(submitted_at__gte=start_date)
        elif date_preset == '30_days':
            start_date = now - timedelta(days=30)
            queryset = queryset.filter(submitted_at__gte=start_date)
    elif date_from and date_to:
        queryset = queryset.filter(
            submitted_at__date__gte=date_from,
            submitted_at__date__lte=date_to
        )
    
    # Apply other filters
    if filters.get('service_type'):
        queryset = queryset.filter(step2__icontains=filters.get('service_type'))
    if filters.get('country'):
        queryset = queryset.filter(country__icontains=filters.get('country'))
    if filters.get('search'):
        search_term = filters.get('search')
        queryset = queryset.filter(
            Q(name__icontains=search_term) |
            Q(email__icontains=search_term) |
            Q(phone__icontains=search_term) |
            Q(step1__icontains=search_term) |
            Q(step8__icontains=search_term)
        )
    
    # Create workbook and worksheet
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "Form Submissions"
    
    # Define headers
    headers = [
        'ID', 'Submission Date', 'Name', 'Email', 'Phone', 'Country',
        'Company Name', 'Service Type', 'When Issue Occurred', 
        'Company Acknowledgment', 'Primary Goal', 'How Heard About Us',
        'Preferred Communication', 'Case Summary', 'IP Address'
    ]
    
    # Style for headers
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
    header_alignment = Alignment(horizontal="center", vertical="center")
    
    # Add headers to worksheet
    for col, header in enumerate(headers, 1):
        cell = worksheet.cell(row=1, column=col, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment
    
    # Add data rows
    submissions = queryset.order_by('-submitted_at')
    
    for row, submission in enumerate(submissions, 2):
        data = [
            submission.id,
            submission.submitted_at.strftime('%Y-%m-%d %H:%M:%S'),
            submission.name,
            submission.email,
            submission.phone,
            submission.country,
            submission.step1 or '',
            submission.step2 or '',
            submission.step3 or '',
            submission.step4 or '',
            submission.step5 or '',
            submission.step6 or '',
            submission.step7 or '',
            submission.step8 or '',
            submission.ip_address or ''
        ]
        
        for col, value in enumerate(data, 1):
            worksheet.cell(row=row, column=col, value=value)
    
    # Auto-adjust column widths
    for column in worksheet.columns:
        max_length = 0
        column_letter = column[0].column_letter
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        adjusted_width = min(max_length + 2, 50)  # Max width of 50
        worksheet.column_dimensions[column_letter].width = adjusted_width
    
    # Create HTTP response
    output = io.BytesIO()
    workbook.save(output)
    output.seek(0)
    
    response = HttpResponse(
        output.getvalue(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    
    filename = f"form_submissions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def submission_stats(request):
    """Admin endpoint to get submission statistics with filtering"""
    
    # Apply filters
    filters = request.query_params
    queryset = Submission.objects.all()
    
    # Date range filtering
    date_from = filters.get('date_from')
    date_to = filters.get('date_to')
    date_preset = filters.get('date_preset')
    
    if date_preset:
        now = timezone.now()
        if date_preset == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            queryset = queryset.filter(submitted_at__gte=start_date)
        elif date_preset == '1_week':
            start_date = now - timedelta(days=7)
            queryset = queryset.filter(submitted_at__gte=start_date)
        elif date_preset == '2_weeks':
            start_date = now - timedelta(days=14)
            queryset = queryset.filter(submitted_at__gte=start_date)
        elif date_preset == '30_days':
            start_date = now - timedelta(days=30)
            queryset = queryset.filter(submitted_at__gte=start_date)
    elif date_from and date_to:
        queryset = queryset.filter(
            submitted_at__date__gte=date_from,
            submitted_at__date__lte=date_to
        )
    
    total_submissions = queryset.count()
    
    # Helper function to get clean breakdown
    def get_breakdown(field_name):
        breakdown = {}
        values = queryset.exclude(**{f'{field_name}__isnull': True}) \
                         .exclude(**{f'{field_name}__exact': ''}) \
                         .values_list(field_name, flat=True)
        
        for value in values:
            if value and value.strip():
                clean_value = value.strip()
                breakdown[clean_value] = breakdown.get(clean_value, 0) + 1
        
        return breakdown
    
    # Get breakdowns
    service_types = get_breakdown('step2')
    countries = get_breakdown('country')
    issue_timeframes = get_breakdown('step3')
    
    # Daily submissions for last 30 days
    thirty_days_ago = timezone.now() - timedelta(days=30)
    daily_stats = []
    for i in range(30):
        date = thirty_days_ago + timedelta(days=i)
        count = queryset.filter(
            submitted_at__date=date.date()
        ).count()
        daily_stats.append({
            'date': date.strftime('%Y-%m-%d'),
            'count': count
        })
    
    return Response({
        'total_submissions': total_submissions,
        'service_type_breakdown': service_types,
        'country_breakdown': countries,
        'issue_timeframe_breakdown': issue_timeframes,
        'daily_submissions': daily_stats,
        'date_range': {
            'from': date_from or 'All time',
            'to': date_to or 'Now',
            'preset': date_preset or 'Custom'
        }
    })