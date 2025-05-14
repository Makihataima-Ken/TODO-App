import json
from pyexpat.errors import messages
from django.http import HttpResponse
from django.shortcuts import redirect, render

import jwt
from rest_framework import generics

from AuthRegisterDjango import settings
from .serializers import RegisterSerializer
from rest_framework.permissions import AllowAny

from .serializers import LoginSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from django.db.models import Q
import bcrypt

from rest_framework.permissions import IsAuthenticated
import requests


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

User = get_user_model()

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        login_input = serializer.validated_data['username_or_email']
        password = serializer.validated_data['password']

        try:
            # Try to find the user by username OR email
            user = User.objects.get(Q(username=login_input) | Q(email=login_input))
        except User.DoesNotExist:
            return Response({'error': 'Account not found'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check password using bcrypt
        if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)
    
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()  # This requires SIMPLE_JWT config
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)
    
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]  # Require JWT toke
    def get(self, request):
        user = request.user
        return Response({
            "id": user.id,
            "username": user.username,
            "email": user.email,
        })
        
# HTML views for user 
def register_page(request):
    if request.method == 'POST':
        # Prepare data to send to API
        data = {
            'username': request.POST.get('username'),
            'email': request.POST.get('email'),
            'password': request.POST.get('password'),
            #'password2': request.POST.get('password2'),
        }
        
        try:
            # Make request to your API endpoint
            response = requests.post(
                'http://localhost:8000/api/register/', 
                data=data
            )
            
            if response.status_code == 201:
                print("Registration successful!")
                return redirect('/login/')
            else:
                # Pass API errors to template
                errors = response.json()
                return render(request, 'accounts/register.html', {'errors': errors})
                
        except requests.exceptions.RequestException:
            messages.error(request, 'Could not connect to the server')
            return render(request, 'accounts/register.html')
    
    return render(request, 'accounts/register.html')


# HTML view for login
def login_page(request):
    if request.method == 'POST':
        # Prepare data to send to API
        data = {
            'username_or_email': request.POST.get('username_or_email'),
            'password': request.POST.get('password'),
        }
        
        try:
            # Make request to your API endpoint
            response = requests.post(
                'http://localhost:8000/api/login/', 
                data=json.dumps(data),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                # Successful login - store tokens
                response_data = response.json()
                request.session['access_token'] = response_data['access']
                request.session['refresh_token'] = response_data['refresh']
                print('Login successful!')
                return redirect('profile_page')
            else:
                # Pass API errors to template
                errors = response.json()
                return render(request, 'accounts/login.html', {'errors': errors})
                
        except requests.exceptions.RequestException:
            messages.error(request, 'Could not connect to the server')
            return render(request, 'accounts/login.html')
    
    return render(request, 'accounts/login.html')

# logout html view
def logout_page(request):
    if request.method == 'POST':
        # Get the refresh token from session
        refresh_token = request.session.get('refresh_token')
        
        if refresh_token:
            try:
                # Call API to blacklist token
                response = requests.post(
                    'http://localhost:8000/api/logout/',
                    data={'refresh_token': refresh_token},
                    headers={'Content-Type': 'application/json'}
                )
                
                # Clear session regardless of API response
                request.session.flush()
                
                if response.status_code == 205:
                    print('Logged out successfully')
                else:
                    print('Logged out (token may still be valid)')
                    
            except requests.exceptions.RequestException:
                request.session.flush()
                print('Logged out (connection error)')
        
        return redirect('login_page')
    
    # If GET request, just show confirmation page
    return render(request, 'accounts/logout.html')

def profile_page(request):
    # Check if user has an access token
    if 'access_token' not in request.session:
        messages.error(request, 'Please login first')
        return redirect('login_page')

    try:
        # Make authenticated request to API
        headers = {
            'Authorization': f'Bearer {request.session["access_token"]}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(
            'http://localhost:8000/api/profile/',
            headers=headers
        )

        if response.status_code == 200:
            profile_data = response.json()
            return render(request, 'accounts/profile.html', {'profile': profile_data})
        
        elif response.status_code == 401:  # Token expired
            if refresh_access_token(request):  # Try to refresh token
                return profile_page(request)  # Retry the request
            messages.error(request, 'Session expired. Please login again')
            return redirect('login_page')
            
        else:
            messages.error(request, 'Failed to load profile')
            return redirect('login_page')

    except requests.exceptions.RequestException:
        messages.error(request, 'Could not connect to the server')
        return redirect('login_page')
    
def refresh_access_token(request):
    """Helper function to refresh expired access token"""
    if 'refresh_token' not in request.session:
        return False
        
    try:
        response = requests.post(
            'http://localhost:8000/api/token/refresh/',
            data={'refresh': request.session['refresh_token']},
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            request.session['access_token'] = response.json()['access']
            return True
    except requests.exceptions.RequestException:
        pass
        
    return False
