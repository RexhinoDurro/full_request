from rest_framework import serializers
from .models import Submission

class SubmissionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new submissions (public endpoint)"""
    
    class Meta:
        model = Submission
        fields = [
            'step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7', 'step8',
            'name', 'email', 'country', 'phone'
        ]
    
    def validate_email(self, value):
        """Validate email format"""
        if not value:
            raise serializers.ValidationError("Email is required")
        return value.lower()
    
    def validate_name(self, value):
        """Validate name field"""
        if not value or len(value.strip()) < 2:
            raise serializers.ValidationError("Name must be at least 2 characters long")
        return value.strip()
    
    def validate_phone(self, value):
        """Validate phone field"""
        if not value:
            raise serializers.ValidationError("Phone number is required")
        return value.strip()

class SubmissionListSerializer(serializers.ModelSerializer):
    """Serializer for listing submissions (admin endpoint)"""
    short_summary = serializers.ReadOnlyField()
    
    class Meta:
        model = Submission
        fields = [
            'id', 'name', 'email', 'phone', 'country',
            'short_summary', 'submitted_at'
        ]

class SubmissionDetailSerializer(serializers.ModelSerializer):
    """Serializer for detailed submission view (admin endpoint)"""
    
    class Meta:
        model = Submission
        fields = '__all__'
        read_only_fields = ['id', 'submitted_at', 'ip_address']