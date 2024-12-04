from rest_framework import serializers
from .models import User, Role, Permission, AuditLog
from bson import ObjectId

# Custom field to handle ObjectId in MongoDB
class ObjectIdField(serializers.Field):
    def to_representation(self, value):
        return str(value)

    def to_internal_value(self, data):
        return ObjectId(data)

# User Serializer
class UserSerializer(serializers.ModelSerializer):
    id = ObjectIdField()  # Serialize ObjectId as string

    class Meta:
        model = User
        fields = '__all__'


# Role Serializer
class RoleSerializer(serializers.ModelSerializer):
    id = ObjectIdField()

    class Meta:
        model = Role
        fields = '__all__'


# Permission Serializer
class PermissionSerializer(serializers.ModelSerializer):
    id = ObjectIdField()

    class Meta:
        model = Permission
        fields = '__all__'


# AuditLog Serializer
class AuditLogSerializer(serializers.ModelSerializer):
    id = ObjectIdField()

    class Meta:
        model = AuditLog
        fields = '__all__'
