from django.db import models
import uuid

class User(models.Model):
    id = models.AutoField(primary_key=True)  # MongoDB will assign an ObjectId
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    roles = models.ManyToManyField('Role', blank=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.username

class Role(models.Model):
    id = models.AutoField(primary_key=True)  # MongoDB will assign an ObjectId
    name = models.CharField(max_length=255, unique=True)
    permissions = models.ManyToManyField('Permission', blank=True)

    def __str__(self):
        return self.name

class Permission(models.Model):
    id = models.AutoField(primary_key=True)  # MongoDB will assign an ObjectId
    name = models.CharField(max_length=255, unique=True)
    resource = models.CharField(max_length=255)
    action = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.resource}:{self.action}"

class AuditLog(models.Model):
    id = models.CharField(primary_key=True, max_length=50, unique=True, default="")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    resource = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    outcome = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = 'auditlog-' + str(uuid.uuid4())
        super(AuditLog, self).save(*args, **kwargs)

    class Meta:
        db_table = 'audit_logs'
