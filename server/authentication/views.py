# authentication/views.py - FIXED VERSION (CSRF Exempt for APIs)

from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
import logging

logger = logging.getLogger('security_monitoring')

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt  # ✅ ADDED: Exempt from CSRF for API endpoints
def login(request):
    """Secure admin login endpoint"""
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        logger.warning(f"Login attempt missing credentials from {request.META.get('REMOTE_ADDR')}")
        return Response({
            'success': False,
            'message': 'Username and password are required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    user = authenticate(username=username, password=password)
    
    if user and user.is_staff:
        refresh = RefreshToken.for_user(user)
        
        # Log successful login
        logger.info(f"Successful admin login: {user.username} from {request.META.get('REMOTE_ADDR')}")
        
        return Response({
            'success': True,
            'message': 'Login successful',
            'tokens': {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
            },
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_staff': user.is_staff,
            }
        }, status=status.HTTP_200_OK)
    
    # Log failed login attempt
    logger.warning(f"Failed login attempt for username '{username}' from {request.META.get('REMOTE_ADDR')}")
    
    return Response({
        'success': False,
        'message': 'Invalid credentials'  # Don't reveal if user exists
    }, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_exempt  # ✅ ADDED: Exempt from CSRF for API endpoints
def logout(request):
    """Secure admin logout endpoint"""
    try:
        refresh_token = request.data.get('refresh_token')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()
        
        logger.info(f"User {request.user.username} logged out from {request.META.get('REMOTE_ADDR')}")
        
        return Response({
            'success': True,
            'message': 'Logged out successfully'
        }, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Logout error for user {request.user.username}: {str(e)}")
        return Response({
            'success': False,
            'message': 'Error during logout'
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@csrf_exempt  # ✅ ADDED: Exempt from CSRF for API endpoints
def profile(request):
    """Get current admin user profile"""
    user = request.user
    
    return Response({
        'success': True,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_staff': user.is_staff,
            'date_joined': user.date_joined,
        }
    }, status=status.HTTP_200_OK)