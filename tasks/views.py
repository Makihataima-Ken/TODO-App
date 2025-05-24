from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
import jwt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from TODOApp import settings
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
    access_token = request.session.get('access_token')
    if not access_token:
        return redirect('login_page')

    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get('user_id')  

        if not user_id:
            return redirect('login_page')

        tasks = Task.objects.filter(user_id=user_id)
        serializer = TaskSerializer(tasks, many=True)
        tasks = serializer.data

        return render(request, 'tasks/task_list.html', {'tasks': tasks})

    except jwt.InvalidTokenError:
        return render(request, 'tasks/error.html', {'error': 'Invalid or expired token. Please log in again.'})



def task_detail(request, pk):
    access_token = request.session.get('access_token')
    if not access_token:
        return redirect('login_page')

    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get('user_id')

        if not user_id:
            return redirect('login_page')

        task = Task.objects.get(pk=pk, user_id=user_id)
        serializer = TaskSerializer(task)
        task_data = serializer.data

        return render(request, 'tasks/task_detail.html', {'task': task_data})

    except jwt.InvalidTokenError:
        return render(request, 'tasks/error.html', {'error': 'Invalid or expired token. Please log in again.'})
    except Exception as e:
        return render(request, 'tasks/error.html', {'error': f'An error occurred: {str(e)}'})

def create_task(request):
    access_token = request.session.get('access_token')
    if not access_token:
        return redirect('login_page')

    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get('user_id')

        if not user_id:
            return redirect('login_page')

        if request.method == 'POST':
            form = TaskForm(request.POST)
            if form.is_valid():
                # Create task with the authenticated user
                task = form.save(commit=False)
                task.user_id = user_id
                task.save()
                return redirect('task_list')
        else:
            form = TaskForm()

        return render(request, 'tasks/task_form.html', {'form': form})

    except jwt.InvalidTokenError:
        return render(request, 'tasks/error.html', {'error': 'Invalid or expired token. Please log in again.'})
    except Exception as e:
        return render(request, 'tasks/error.html', {'error': f'An error occurred: {str(e)}'})

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
