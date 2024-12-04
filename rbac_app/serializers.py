from rest_framework import serializers
from .models import User, Role, Permission, AuditLog


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['_id', 'name', 'resource', 'action']


class RoleSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True, read_only=True)
    permissions_ids = serializers.PrimaryKeyRelatedField(
        queryset=Permission.objects.all(),
        many=True,
        write_only=True,
        source='permissions'
    )

    class Meta:
        model = Role
        fields = ['_id', 'name', 'permissions', 'permissions_ids']


class UserSerializer(serializers.ModelSerializer):
    roles = RoleSerializer(many=True, read_only=True)
    roles_ids = serializers.PrimaryKeyRelatedField(
        queryset=Role.objects.all(),
        many=True,
        write_only=True,
        source='roles'
    )

    class Meta:
        model = User
        fields = ['_id', 'username', 'email', 'is_active', 'is_admin', 'roles', 'roles_ids']


class AuditLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = AuditLog
        fields = ['_id', 'user', 'resource', 'action', 'outcome', 'timestamp']
