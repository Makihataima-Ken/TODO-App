from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import Task
from .forms import TaskForm
from .serializers import TaskSerializer
import requests
import json

# ========== API VIEWS ==========

class TaskAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        if pk:
            task = get_object_or_404(Task, pk=pk, user=request.user)
            serializer = TaskSerializer(task)
            return Response(serializer.data)
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


# ========== HTML VIEWS ==========

API_BASE_URL = 'http://localhost:8000/api/tasks/'

def task_list(request):
    if not request.session.get('access_token'):
        return redirect('login_page')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    try:
        response = requests.get(API_BASE_URL, headers=headers)

        if response.status_code == 200:
            tasks = response.json()
            return render(request, 'tasks/task_list.html', {'tasks': tasks})

        if response.status_code == 401 and refresh_access_token(request):
            return task_list(request)

        return render(request, 'tasks/error.html', {'error': f"Error {response.status_code}: Unable to fetch tasks."})

    except requests.exceptions.RequestException:
        return render(request, 'tasks/error.html', {'error': 'API connection failed.'})


def task_detail(request, pk):
    # Check authentication
    if not request.session.get('access_token'):
        return redirect('login_page')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    
    try:
        # Make API request for specific task
        response = requests.get(f"{API_BASE_URL}{pk}/", headers=headers)

        if response.status_code == 200:
            task = response.json()
            return render(request, 'tasks/task_detail.html', {'task': task})

        # Handle token expiration
        if response.status_code == 401 and refresh_access_token(request):
            return task_detail(request, pk)  # Retry with new token

        # Handle other errors
        error_message = f"Error {response.status_code}: Unable to fetch task details."
        if response.status_code == 404:
            error_message = "Task not found or you don't have permission to view it."
        return render(request, 'tasks/error.html', {'error': error_message})

    except requests.exceptions.RequestException as e:
        return render(request, 'tasks/error.html', {'error': f'API connection failed: {str(e)}'})


def create_task(request):
    if not request.session.get('access_token'):
        return redirect('login_page')

    form = TaskForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        headers = {
            'Authorization': f'Bearer {request.session["access_token"]}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(API_BASE_URL, headers=headers, data=json.dumps(form.cleaned_data))

            if response.status_code == 201:
                return redirect('task_list')

            if response.status_code == 401 and refresh_access_token(request):
                return create_task(request)

            return render(request, 'tasks/task_form.html', {'form': form, 'errors': response.json()})

        except requests.exceptions.RequestException:
            return render(request, 'tasks/error.html', {'error': 'API connection failed.'})

    return render(request, 'tasks/task_form.html', {'form': form})


def update_task(request, pk):
    if not request.session.get('access_token'):
        return redirect('login_page')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    try:
        response = requests.get(f'{API_BASE_URL}{pk}/', headers=headers)

        if response.status_code == 401 and refresh_access_token(request):
            return update_task(request, pk)

        if response.status_code != 200:
            return render(request, 'tasks/error.html', {'error': f'Task not found. ({response.status_code})'})

        task_data = response.json()
        form = TaskForm(request.POST or None, initial=task_data)

        if request.method == 'POST' and form.is_valid():
            try:
                update_response = requests.put(
                    f'{API_BASE_URL}{pk}/',
                    headers={**headers, 'Content-Type': 'application/json'},
                    data=json.dumps(form.cleaned_data)
                )

                if update_response.status_code == 200:
                    return redirect('task_list')

                return render(request, 'tasks/task_form.html', {'form': form, 'errors': update_response.json()})

            except requests.exceptions.RequestException:
                return render(request, 'tasks/error.html', {'error': 'API connection failed.'})

        return render(request, 'tasks/task_form.html', {'form': form, 'task': task_data})

    except requests.exceptions.RequestException:
        return render(request, 'tasks/error.html', {'error': 'API connection failed.'})


def delete_task(request, pk):
    if not request.session.get('access_token'):
        return redirect('login_page')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    if request.method == 'POST':
        try:
            response = requests.delete(f'{API_BASE_URL}{pk}/', headers=headers)

            if response.status_code == 204:
                return redirect('task_list')

            return render(request, 'tasks/error.html', {'error': 'Failed to delete task.'})

        except requests.exceptions.RequestException:
            return render(request, 'tasks/error.html', {'error': 'API connection failed.'})

    try:
        response = requests.get(f'{API_BASE_URL}{pk}/', headers=headers)

        if response.status_code == 200:
            task = response.json()
            return render(request, 'tasks/task_confirm_delete.html', {'task': task})

        return render(request, 'tasks/error.html', {'error': 'Task not found.'})

    except requests.exceptions.RequestException:
        return render(request, 'tasks/error.html', {'error': 'API connection failed.'})


# ========== Token Refresh Helper ==========

def refresh_access_token(request):
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
            request.session['access_token'] = response.json().get('access')
            return True
    except requests.exceptions.RequestException:
        return False

    return False
