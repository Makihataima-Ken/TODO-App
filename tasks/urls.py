from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import (
    TaskAPIView,
    task_list,
    create_task,
    update_task,
    delete_task,
)

urlpatterns = [
    # API Endpoints
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/tasks/', TaskAPIView.as_view(), name='task-api-list'),
    path('api/tasks/<int:pk>/', TaskAPIView.as_view(), name='task-api-detail'),
    
    # HTML Endpoints
    path('tasks/', task_list, name='task_list'),
    path('tasks/create/', create_task, name='create_task'),
    path('tasks/update/<int:pk>/', update_task, name='update_task'),
    path('tasks/delete/<int:pk>/', delete_task, name='delete_task'),
]