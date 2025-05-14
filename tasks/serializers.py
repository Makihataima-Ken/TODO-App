from rest_framework import serializers
from .models import Task

class TaskSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = Task
        fields = ['id', 'user', 'title', 'description', 'status', 'status_display', 'created', 'updated']
        read_only_fields = ['user', 'created', 'updated']

    def create(self, validated_data):
        # Automatically set the user to the current user
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)