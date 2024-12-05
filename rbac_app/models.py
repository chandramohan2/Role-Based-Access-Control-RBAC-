from django.db import models


class Permission(models.Model):
    name = models.CharField(max_length=100, unique=True)  # e.g., "View Users"
    resource = models.CharField(max_length=100)          # e.g., "User"
    action = models.CharField(max_length=50)             # e.g., "View", "Edit"

    def __str__(self):
        return f"{self.name} ({self.resource}:{self.action})"


class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)  # e.g., "Admin", "Editor"
    permissions = models.ManyToManyField(Permission, related_name="roles", blank=True)

    def __str__(self):
        return self.name


class User(models.Model):
    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=100)  # Use hashing in production!
    email = models.EmailField(unique=True, null=True, blank=True)
    roles = models.ManyToManyField(Role, related_name="users", blank=True)

    def __str__(self):
        return self.username


class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="audit_logs")
    resource = models.CharField(max_length=100)
    action = models.CharField(max_length=50)
    outcome = models.CharField(max_length=50)  # e.g., "Success", "Failure"
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.resource}:{self.action} ({self.outcome})"
