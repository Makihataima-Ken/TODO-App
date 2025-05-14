from django.db import models
from django.contrib.auth.models import User

from TODOApp import settings

class task(models.Model):
    class Status(models.TextChoices):
        TODO = 'TD', 'To Do'
        IN_PROGRESS = 'IP', 'In Progress'
        DONE = 'DN', 'Done'
    
    user = models.ForeignKey(User, on_delete= models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    dueDate = models.DateField(blank=True)
    # Status field using the enum
    status = models.CharField(
        max_length=2,
        choices=Status.choices,
        default=Status.TODO
    )
    # basic info for record
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"
    
    class Meta:
        ordering = ['status', '-created']  # Order by status then newest first
        verbose_name = 'Task'
        verbose_name_plural = 'Tasks'
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['user', 'status']),
        ]
