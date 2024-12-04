from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User, Role, Permission, AuditLog
from django.core.exceptions import ObjectDoesNotExist

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ObjectDoesNotExist
from .models import User, Role  # Assuming you have User and Role models defined
from bson import ObjectId

class UserManagementView(APIView):
    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        roles = request.data.get('roles', [])
        is_active = request.data.get('is_active', True)
        is_admin = request.data.get('is_admin', False)

        if not username or not email:
            return Response({
                "success": False,
                "message": "Username and email are required."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create the user
            user = User.objects.create(username=username, email=email, is_active=is_active, is_admin=is_admin)

            # Loop through the role ids and add them
            for role_id in roles:
                # Convert string to ObjectId
                role_id = ObjectId(role_id) if isinstance(role_id, str) else role_id
                try:
                    role = Role.objects.get(id=role_id)
                    user.roles.add(role)
                except Role.DoesNotExist:
                    return Response({
                        "success": False,
                        "message": f"Role with id {role_id} does not exist."
                    }, status=status.HTTP_404_NOT_FOUND)

            return Response({
                "success": True,
                "message": "User created successfully",
                "data": {
                    "username": user.username,
                    "email": user.email,
                    "roles": [role.name for role in user.roles.all()],
                    "is_active": user.is_active,
                    "is_admin": user.is_admin,
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                "success": False,
                "message": f"Error: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        users = User.objects.all()
        user_data = [{
            "username": user.username,
            "email": user.email,
            "roles": [role.name for role in user.roles.all()],
            "is_active": user.is_active,
            "is_admin": user.is_admin,
        } for user in users]

        return Response({
            "success": True,
            "data": user_data
        })


class RoleManagementView(APIView):
    def post(self, request):
        name = request.data.get('name')
        permissions_ids = request.data.get('permissions_ids', [])

        if not name:
            return Response({
                "success": False,
                "message": "Role name is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            role = Role.objects.create(name=name)
            for permission_id in permissions_ids:
                permission = Permission.objects.get(id=permission_id)
                role.permissions.add(permission)

            return Response({
                "success": True,
                "message": "Role created successfully",
                "data": {
                    "name": role.name,
                    "permissions": [permission.name for permission in role.permissions.all()]
                }
            }, status=status.HTTP_201_CREATED)
        except ObjectDoesNotExist as e:
            return Response({
                "success": False,
                "message": f"Permission not found: {str(e)}"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Error: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        roles = Role.objects.all()
        role_data = [{
            "name": role.name,
            "permissions": [permission.name for permission in role.permissions.all()]
        } for role in roles]

        return Response({
            "success": True,
            "data": role_data
        })

class PermissionManagementView(APIView):
    def post(self, request):
        name = request.data.get('name')
        resource = request.data.get('resource')
        action = request.data.get('action')

        if not name or not resource or not action:
            return Response({
                "success": False,
                "message": "Name, resource, and action are required."
            }, status=status.HTTP_400_BAD_REQUEST)

        permission = Permission.objects.create(name=name, resource=resource, action=action)

        return Response({
            "success": True,
            "message": "Permission created successfully",
            "data": {
                "name": permission.name,
                "resource": permission.resource,
                "action": permission.action
            }
        }, status=status.HTTP_201_CREATED)

    def get(self, request):
        permissions = Permission.objects.all()
        permission_data = [{
            "name": permission.name,
            "resource": permission.resource,
            "action": permission.action
        } for permission in permissions]

        return Response({
            "success": True,
            "data": permission_data
        })

class AccessValidationView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        permission_name = request.data.get('permission_name')

        try:
            user = User.objects.get(id=user_id)
            permission = Permission.objects.get(name=permission_name)

            has_permission = False
            for role in user.roles.all():
                if permission in role.permissions.all():
                    has_permission = True
                    break

            if has_permission:
                return Response({
                    "success": True,
                    "message": "Access granted"
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "success": False,
                    "message": "Access denied"
                }, status=status.HTTP_403_FORBIDDEN)

        except User.DoesNotExist:
            return Response({
                "success": False,
                "message": "User not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Permission.DoesNotExist:
            return Response({
                "success": False,
                "message": "Permission not found"
            }, status=status.HTTP_404_NOT_FOUND)

class AuditLogView(APIView):
    def get(self, request):
        logs = AuditLog.objects.all()
        log_data = [{
            "user": log.user.username,
            "resource": log.resource,
            "action": log.action,
            "outcome": log.outcome,
            "timestamp": log.timestamp
        } for log in logs]

        return Response({
            "success": True,
            "data": log_data
        })
