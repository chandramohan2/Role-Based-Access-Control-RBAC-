from django.db import models

class User(models.Model):
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    roles = models.ManyToManyField('Role', blank=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.username

class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)
    permissions = models.ManyToManyField('Permission', blank=True)

    def __str__(self):
        return self.name

class Permission(models.Model):
    name = models.CharField(max_length=255, unique=True)  # e.g., "API_ONE"
    resource = models.CharField(max_length=255)           # e.g., "API"
    action = models.CharField(max_length=255)             # e.g., "read/write"

    def __str__(self):
        return f"{self.resource}:{self.action}"

class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    resource = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    outcome = models.CharField(max_length=50)  # "granted" or "denied"
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.resource} - {self.outcome} - {self.timestamp}"
