from rest_framework import serializers
from .models import User, Role, Permission, AuditLog

class UserSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)  

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'roles', 'is_active', 'is_admin']


class RoleSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    class Meta:
        model = Role
        fields = ['id', 'name', 'permissions']


class PermissionSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    class Meta:
        model = Permission
        fields = ['id', 'name', 'resource', 'action']


class AuditLogSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    class Meta:
        model = AuditLog
        fields = ['id', 'user', 'resource', 'action', 'outcome', 'timestamp']
