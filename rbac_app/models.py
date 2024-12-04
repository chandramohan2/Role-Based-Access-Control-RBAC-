from django.db import models
from bson import ObjectId
from djongo import models as djongo_models


class ObjectIdField(djongo_models.ObjectIdField):
    """
    A custom ObjectId field that uses MongoDB's default ObjectId for primary keys.
    """
    def __init__(self, *args, **kwargs):
        kwargs['default'] = ObjectId
        super().__init__(*args, **kwargs)


class User(models.Model):
    _id = ObjectIdField(primary_key=True)
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    roles = models.ManyToManyField('Role', blank=True)  # Many-to-Many relationship with Role
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.username


class Role(models.Model):
    _id = ObjectIdField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    permissions = models.ManyToManyField('Permission', blank=True)  # Many-to-Many relationship with Permission

    def __str__(self):
        return self.name


class Permission(models.Model):
    _id = ObjectIdField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    resource = models.CharField(max_length=255)
    action = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.resource}:{self.action}"


class AuditLog(models.Model):
    _id = ObjectIdField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    resource = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    outcome = models.CharField(max_length=50)  # "granted" or "denied"
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'
