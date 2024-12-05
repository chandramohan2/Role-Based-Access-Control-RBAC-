# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from .models import User, Role, Permission, AuditLog

class UserManagementView(APIView):
    @transaction.atomic
    def post(self, request):
        try:
            username = request.data.get('username')
            email = request.data.get('email')
            role_ids = request.data.get('roles', [])
            is_active = request.data.get('is_active', True)
            is_admin = request.data.get('is_admin', False)

            if not username or not email:
                return Response({
                    "success": False,
                    "message": "Username and email are required."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create user
            user = User.objects.create(
                username=username,
                email=email,
                is_active=is_active,
                is_admin=is_admin
            )

            # Add roles
            roles = Role.objects.filter(id__in=role_ids)
            user.roles.add(*roles)

            # Create audit log
            AuditLog.objects.create(
                user=request.user,
                resource='user',
                action='create',
                outcome='success',
                details={'created_user_id': user.id}
            )

            return Response({
                "success": True,
                "message": "User created successfully",
                "data": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "roles": list(user.roles.values('id', 'name')),
                    "is_active": user.is_active,
                    "is_admin": user.is_admin,
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            transaction.set_rollback(True)
            AuditLog.objects.create(
                user=request.user,
                resource='user',
                action='create',
                outcome='failure',
                details={'error': str(e)}
            )
            return Response({
                "success": False,
                "message": f"Error: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RoleManagementView(APIView):
    @transaction.atomic
    def post(self, request):
        try:
            name = request.data.get('name')
            permission_ids = request.data.get('permissions', [])

            if not name:
                return Response({
                    "success": False,
                    "message": "Role name is required."
                }, status=status.HTTP_400_BAD_REQUEST)

            role = Role.objects.create(name=name)
            permissions = Permission.objects.filter(id__in=permission_ids)
            role.permissions.add(*permissions)

            AuditLog.objects.create(
                user=request.user,
                resource='role',
                action='create',
                outcome='success',
                details={'role_id': role.id}
            )

            return Response({
                "success": True,
                "message": "Role created successfully",
                "data": {
                    "id": role.id,
                    "name": role.name,
                    "permissions": list(role.permissions.values('id', 'name'))
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            transaction.set_rollback(True)
            AuditLog.objects.create(
                user=request.user,
                resource='role',
                action='create',
                outcome='failure',
                details={'error': str(e)}
            )
            return Response({
                "success": False,
                "message": f"Error: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        roles = Role.objects.prefetch_related('permissions').all()
        role_data = [{
            "id": role.id,
            "name": role.name,
            "permissions": list(role.permissions.values('id', 'name'))
        } for role in roles]

        return Response({
            "success": True,
            "data": role_data
        })

class PermissionManagementView(APIView):
    @transaction.atomic
    def post(self, request):
        try:
            name = request.data.get('name')
            resource = request.data.get('resource')
            action = request.data.get('action')

            if not all([name, resource, action]):
                return Response({
                    "success": False,
                    "message": "Name, resource, and action are required."
                }, status=status.HTTP_400_BAD_REQUEST)

            permission = Permission.objects.create(
                name=name,
                resource=resource,
                action=action
            )

            AuditLog.objects.create(
                user=request.user,
                resource='permission',
                action='create',
                outcome='success',
                details={'permission_id': permission.id}
            )

            return Response({
                "success": True,
                "message": "Permission created successfully",
                "data": {
                    "id": permission.id,
                    "name": permission.name,
                    "resource": permission.resource,
                    "action": permission.action
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            transaction.set_rollback(True)
            AuditLog.objects.create(
                user=request.user,
                resource='permission',
                action='create',
                outcome='failure',
                details={'error': str(e)}
            )
            return Response({
                "success": False,
                "message": f"Error: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        permissions = Permission.objects.all()
        permission_data = list(permissions.values('id', 'name', 'resource', 'action'))
        return Response({
            "success": True,
            "data": permission_data
        })

class AccessValidationView(APIView):
    def post(self, request):
        try:
            user_id = request.data.get('user_id')
            resource = request.data.get('resource')
            action = request.data.get('action')

            if not all([user_id, resource, action]):
                return Response({
                    "success": False,
                    "message": "User ID, resource, and action are required."
                }, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.prefetch_related('roles__permissions').get(id=user_id)
            
            # Check if user has permission through any of their roles
            has_permission = user.roles.filter(
                permissions__resource=resource,
                permissions__action=action
            ).exists()

            outcome = 'granted' if has_permission else 'denied'
            AuditLog.objects.create(
                user=user,
                resource=resource,
                action=action,
                outcome=outcome,
                details={
                    'requester_id': request.user.id,
                    'validation_type': 'access_check'
                }
            )

            if has_permission:
                return Response({
                    "success": True,
                    "message": "Access granted"
                })
            
            return Response({
                "success": False,
                "message": "Access denied"
            }, status=status.HTTP_403_FORBIDDEN)

        except User.DoesNotExist:
            return Response({
                "success": False,
                "message": "User not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Error: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AuditLogView(APIView):
    def get(self, request):
        logs = AuditLog.objects.select_related('user').all()
        log_data = [{
            "id": str(log.id),
            "user": log.user.username,
            "resource": log.resource,
            "action": log.action,
            "outcome": log.outcome,
            "details": log.details,
            "timestamp": log.timestamp
        } for log in logs]

        return Response({
            "success": True,
            "data": log_data
        })