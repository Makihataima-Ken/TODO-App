from rest_framework import serializers
from .models import Task
from django.contrib.auth import get_user_model

User = get_user_model()

class TaskSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    user = serializers.PrimaryKeyRelatedField(read_only=True)
    
    class Meta:
        model = Task
        fields = ['id', 'user', 'title', 'description', 'status', 'status_display', 'created', 'updated']
        read_only_fields = ['user', 'created', 'updated']
    
    def validate_status(self, value):
        """Validate status field against enum choices"""
        if value not in [choice[0] for choice in Task.Status.choices]:
            raise serializers.ValidationError("Invalid status value")
        return value