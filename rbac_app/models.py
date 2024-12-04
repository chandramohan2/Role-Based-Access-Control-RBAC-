from djongo import models
from bson import ObjectId  # For ObjectId

# Custom User Model
class User(models.Model):
    id = models.ObjectIdField(primary_key=True)  # MongoDB's ObjectId as primary key
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    roles = models.ArrayField(model_container="Role", blank=True)  # Array of Role objects
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    class Meta:
        db_table = 'users'  # Set the MongoDB collection name to 'users'

    def __str__(self):
        return self.username


# Role Model
class Role(models.Model):
    id = models.ObjectIdField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    permissions = models.ArrayField(model_container="Permission", blank=True)  # Array of Permission objects

    class Meta:
        db_table = 'roles'  # Set the MongoDB collection name to 'roles'

    def __str__(self):
        return self.name


# Permission Model
class Permission(models.Model):
    id = models.ObjectIdField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    resource = models.CharField(max_length=255)
    action = models.CharField(max_length=255)

    class Meta:
        db_table = 'permissions'  # Set the MongoDB collection name to 'permissions'

    def __str__(self):
        return f"{self.resource}:{self.action}"


# Audit Log Model
class AuditLog(models.Model):
    id = models.ObjectIdField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    resource = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    outcome = models.CharField(max_length=50)  # "granted" or "denied"
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'  # Set the MongoDB collection name to 'audit_logs'

    def __str__(self):
        return f"{self.user.username} - {self.resource} - {self.outcome} - {self.timestamp}"
