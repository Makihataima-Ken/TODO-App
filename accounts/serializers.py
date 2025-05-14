from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.validators import UniqueValidator
import bcrypt

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ('username', 'email', 'password')

    def create(self, validated_data):
        
        hashed_password = bcrypt.hashpw(
        validated_data['password'].encode('utf-8'),
        bcrypt.gensalt()
        ).decode('utf-8')
        
        user = User(
        username=validated_data['username'],
        email=validated_data['email'],
        )
        
        user.password = hashed_password  
        user.save()
        
        return user

class LoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField()
    password = serializers.CharField()