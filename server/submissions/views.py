from django.http import HttpResponse
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from datetime import datetime
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
    """Admin endpoint to list all submissions"""
    queryset = Submission.objects.all()
    serializer_class = SubmissionListSerializer
    permission_classes = [IsAuthenticated]

class SubmissionDetailView(generics.RetrieveAPIView):
    """Admin endpoint to view detailed submission"""
    queryset = Submission.objects.all()
    serializer_class = SubmissionDetailSerializer
    permission_classes = [IsAuthenticated]

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_submissions_excel(request):
    """Admin endpoint to download submissions as Excel file"""
    
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
    submissions = Submission.objects.all().order_by('-submitted_at')
    
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
    """Admin endpoint to get submission statistics"""
    total_submissions = Submission.objects.count()
    
    # Group by submission date (last 30 days)
    from django.utils import timezone
    from datetime import timedelta
    
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_submissions = Submission.objects.filter(submitted_at__gte=thirty_days_ago).count()
    
    # Group by service type (step2)
    service_types = {}
    for submission in Submission.objects.exclude(step2__isnull=True).exclude(step2__exact=''):
        service_type = submission.step2
        service_types[service_type] = service_types.get(service_type, 0) + 1
    
    return Response({
        'total_submissions': total_submissions,
        'recent_submissions_30_days': recent_submissions,
        'service_type_breakdown': service_types,
    })