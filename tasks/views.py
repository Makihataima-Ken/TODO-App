from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import Task
from .forms import TaskForm
from .serializers import TaskSerializer
from django.shortcuts import get_object_or_404
import requests
import json

# API Views
class TaskAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk=None):
        if pk:
            task = get_object_or_404(Task, pk=pk, user=request.user)
            serializer = TaskSerializer(task)
            return Response(serializer.data)
        else:
            tasks = Task.objects.filter(user=request.user)
            serializer = TaskSerializer(tasks, many=True)
            return Response(serializer.data)
    
    def post(self, request):
        serializer = TaskSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, pk):
        task = get_object_or_404(Task, pk=pk, user=request.user)
        serializer = TaskSerializer(task, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, pk):
        task = get_object_or_404(Task, pk=pk, user=request.user)
        serializer = TaskSerializer(task, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        task = get_object_or_404(Task, pk=pk, user=request.user)
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

# HTML Views
def task_list(request):
    # Get JWT token from session
    access_token = request.session.get('access_token')
    
    if not access_token:
        return redirect('login')
    
    try:
        # Call our API to get tasks
        response = requests.get(
            'http://localhost:8000/api/tasks/',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        if response.status_code == 200:
            tasks = response.json()
            return render(request, 'tasks/task_list.html', {'tasks': tasks})
        elif response.status_code == 401:  # Token expired
            if refresh_access_token(request):
                return task_list(request)  # Retry the request
            return redirect('login')
        else:
            return render(request, 'tasks/error.html', {'error': 'Failed to fetch tasks'})
    except requests.exceptions.RequestException:
        return render(request, 'tasks/error.html', {'error': 'API connection failed'})

def create_task(request):
    access_token = request.session.get('access_token')
    
    if request.method == 'POST':
        form = TaskForm(request.POST)
        if form.is_valid():
            try:
                response = requests.post(
                    'http://localhost:8000/api/tasks/',
                    headers={
                        'Authorization': f'Bearer {access_token}',
                        'Content-Type': 'application/json'
                    },
                    data=json.dumps(form.cleaned_data)
                )
                
                if response.status_code == 201:
                    return redirect('task_list')
                else:
                    errors = response.json()
                    return render(request, 'tasks/task_form.html', {'form': form, 'errors': errors})
            except requests.exceptions.RequestException:
                return render(request, 'tasks/error.html', {'error': 'API connection failed'})
    else:
        form = TaskForm()
    
    return render(request, 'tasks/task_form.html', {'form': form})


def update_task(request, pk):
    access_token = request.session.get('access_token')
    
    try:
        # Get existing task
        response = requests.get(
            f'http://localhost:8000/api/tasks/{pk}/',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        if response.status_code != 200:
            return render(request, 'tasks/error.html', {'error': 'Task not found'})
        
        task = response.json()
        
        if request.method == 'POST':
            form = TaskForm(request.POST)
            if form.is_valid():
                try:
                    response = requests.put(
                        f'http://localhost:8000/api/tasks/{pk}/',
                        headers={
                            'Authorization': f'Bearer {access_token}',
                            'Content-Type': 'application/json'
                        },
                        data=json.dumps(form.cleaned_data)
                    )
                    
                    if response.status_code == 200:
                        return redirect('task_list')
                    else:
                        errors = response.json()
                        return render(request, 'tasks/task_form.html', {'form': form, 'errors': errors})
                except requests.exceptions.RequestException:
                    return render(request, 'tasks/error.html', {'error': 'API connection failed'})
        else:
            form = TaskForm(initial=task)
        
        return render(request, 'tasks/task_form.html', {'form': form, 'task': task})
    
    except requests.exceptions.RequestException:
        return render(request, 'tasks/error.html', {'error': 'API connection failed'})


def delete_task(request, pk):
    access_token = request.session.get('access_token')
    
    if request.method == 'POST':
        try:
            response = requests.delete(
                f'http://localhost:8000/api/tasks/{pk}/',
                headers={'Authorization': f'Bearer {access_token}'}
            )
            
            if response.status_code == 204:
                return redirect('task_list')
            else:
                return render(request, 'tasks/error.html', {'error': 'Failed to delete task'})
        except requests.exceptions.RequestException:
            return render(request, 'tasks/error.html', {'error': 'API connection failed'})
    
    try:
        response = requests.get(
            f'http://localhost:8000/api/tasks/{pk}/',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        if response.status_code == 200:
            task = response.json()
            return render(request, 'tasks/task_confirm_delete.html', {'task': task})
        else:
            return render(request, 'tasks/error.html', {'error': 'Task not found'})
    except requests.exceptions.RequestException:
        return render(request, 'tasks/error.html', {'error': 'API connection failed'})

def refresh_access_token(request):
    """Helper function to refresh expired access token"""
    refresh_token = request.session.get('refresh_token')
    if not refresh_token:
        return False
        
    try:
        response = requests.post(
            'http://localhost:8000/api/token/refresh/',
            headers={'Content-Type': 'application/json'},
            data=json.dumps({'refresh': refresh_token})
        )
        
        if response.status_code == 200:
            request.session['access_token'] = response.json()['access']
            return True
    except requests.exceptions.RequestException:
        pass
        
    return False