from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import transaction
from django.core.paginator import Paginator
from .models import User, Role, Permission, AuditLog
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

class BaseAPIView(APIView):
    """Base API View with common functionality"""
    permission_classes = [IsAuthenticated]
    
    def create_audit_log(self, user: Any, resource: str, action: str, 
                        outcome: str, details: Optional[Dict] = None) -> None:
        """
        Create an audit log entry with error handling
        """
        try:
            if hasattr(user, 'is_authenticated') and not user.is_authenticated:
                user, _ = User.objects.get_or_create(
                    username='system',
                    defaults={'email': 'system@example.com', 'is_admin': True}
                )

            AuditLog.objects.create(
                user=user,
                resource=resource,
                action=action,
                outcome=outcome,
                details=details
            )
        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}")

class PermissionManagementView(BaseAPIView):
    """Handle Permission CRUD operations"""

    @transaction.atomic
    def post(self, request):
        """Create a new permission"""
        try:
            # Validate required fields
            required_fields = {'name', 'resource', 'action'}
            if not all(field in request.data for field in required_fields):
                return Response({
                    "success": False,
                    "message": "Missing required fields",
                    "required": list(required_fields)
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create permission
            permission = Permission.objects.create(
                name=request.data['name'],
                resource=request.data['resource'],
                action=request.data['action']
            )

            self.create_audit_log(
                request.user,
                'permission',
                'create',
                'success',
                {'permission_id': permission.id}
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

        except ValidationError as e:
            transaction.set_rollback(True)
            self.create_audit_log(
                request.user,
                'permission',
                'create',
                'failure',
                {'error': str(e)}
            )
            return Response({
                "success": False,
                "message": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            transaction.set_rollback(True)
            logger.error(f"Permission creation failed: {str(e)}")
            self.create_audit_log(
                request.user,
                'permission',
                'create',
                'failure',
                {'error': str(e)}
            )
            return Response({
                "success": False,
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        """List all permissions with pagination"""
        try:
            page_size = int(request.query_params.get('page_size', 10))
            page_number = int(request.query_params.get('page', 1))
            
            permissions = Permission.objects.all()
            paginator = Paginator(permissions, page_size)
            page_obj = paginator.get_page(page_number)

            return Response({
                "success": True,
                "data": list(page_obj.object_list.values('id', 'name', 'resource', 'action')),
                "pagination": {
                    "total_pages": paginator.num_pages,
                    "current_page": page_number,
                    "total_items": paginator.count
                }
            })
        except Exception as e:
            logger.error(f"Permission listing failed: {str(e)}")
            return Response({
                "success": False,
                "message": "Failed to retrieve permissions"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RoleManagementView(BaseAPIView):
    """Handle Role CRUD operations"""

    @transaction.atomic
    def post(self, request):
        """Create a new role"""
        try:
            # Validate required fields
            if 'name' not in request.data:
                return Response({
                    "success": False,
                    "message": "Role name is required"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create role
            role = Role.objects.create(name=request.data['name'])

            # Add permissions if provided
            permission_ids = request.data.get('permissions', [])
            if permission_ids:
                permissions = Permission.objects.filter(id__in=permission_ids)
                role.permissions.add(*permissions)

            self.create_audit_log(
                request.user,
                'role',
                'create',
                'success',
                {'role_id': role.id}
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
            logger.error(f"Role creation failed: {str(e)}")
            self.create_audit_log(
                request.user,
                'role',
                'create',
                'failure',
                {'error': str(e)}
            )
            return Response({
                "success": False,
                "message": "Failed to create role"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        """List all roles with their permissions"""
        try:
            page_size = int(request.query_params.get('page_size', 10))
            page_number = int(request.query_params.get('page', 1))

            roles = Role.objects.prefetch_related('permissions').all()
            paginator = Paginator(roles, page_size)
            page_obj = paginator.get_page(page_number)

            role_data = [{
                "id": role.id,
                "name": role.name,
                "permissions": list(role.permissions.values('id', 'name'))
            } for role in page_obj.object_list]

            return Response({
                "success": True,
                "data": role_data,
                "pagination": {
                    "total_pages": paginator.num_pages,
                    "current_page": page_number,
                    "total_items": paginator.count
                }
            })
        except Exception as e:
            logger.error(f"Role listing failed: {str(e)}")
            return Response({
                "success": False,
                "message": "Failed to retrieve roles"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserManagementView(BaseAPIView):
    """Handle User CRUD operations"""

    @transaction.atomic
    def post(self, request):
        """Create a new user"""
        try:
            # Validate required fields
            required_fields = {'username', 'email'}
            if not all(field in request.data for field in required_fields):
                return Response({
                    "success": False,
                    "message": "Username and email are required"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create user
            user = User.objects.create(
                username=request.data['username'],
                email=request.data['email'],
                is_active=request.data.get('is_active', True),
                is_admin=request.data.get('is_admin', False)
            )

            # Assign roles if provided
            role_ids = request.data.get('roles', [])
            if role_ids:
                roles = Role.objects.filter(id__in=role_ids)
                user.roles.add(*roles)

            self.create_audit_log(
                request.user,
                'user',
                'create',
                'success',
                {'created_user_id': user.id}
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
                    "is_admin": user.is_admin
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            transaction.set_rollback(True)
            logger.error(f"User creation failed: {str(e)}")
            self.create_audit_log(
                request.user,
                'user',
                'create',
                'failure',
                {'error': str(e)}
            )
            return Response({
                "success": False,
                "message": "Failed to create user"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AccessValidationView(BaseAPIView):
    """Handle access validation requests"""

    def post(self, request):
        """Validate user access to a resource"""
        try:
            # Validate required fields
            required_fields = {'user_id', 'resource', 'action'}
            if not all(field in request.data for field in required_fields):
                return Response({
                    "success": False,
                    "message": "User ID, resource, and action are required"
                }, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.prefetch_related('roles__permissions').get(id=request.data['user_id'])
            
            # Check permission
            has_permission = user.roles.filter(
                permissions__resource=request.data['resource'],
                permissions__action=request.data['action']
            ).exists()

            outcome = 'granted' if has_permission else 'denied'
            self.create_audit_log(
                user,
                request.data['resource'],
                request.data['action'],
                outcome,
                {
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
            logger.error(f"Access validation failed: {str(e)}")
            return Response({
                "success": False,
                "message": "Failed to validate access"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AuditLogView(BaseAPIView):
    """Handle audit log retrieval"""

    def get(self, request):
        """Retrieve audit logs with filtering and pagination"""
        try:
            page_size = int(request.query_params.get('page_size', 10))
            page_number = int(request.query_params.get('page', 1))
            
            # Apply filters if provided
            filters = {}
            if 'user_id' in request.query_params:
                filters['user_id'] = request.query_params['user_id']
            if 'resource' in request.query_params:
                filters['resource'] = request.query_params['resource']
            if 'action' in request.query_params:
                filters['action'] = request.query_params['action']
            if 'outcome' in request.query_params:
                filters['outcome'] = request.query_params['outcome']

            logs = AuditLog.objects.select_related('user').filter(**filters)
            paginator = Paginator(logs, page_size)
            page_obj = paginator.get_page(page_number)

            log_data = [{
                "id": str(log.id),
                "user": log.user.username,
                "resource": log.resource,
                "action": log.action,
                "outcome": log.outcome,
                "details": log.details,
                "timestamp": log.timestamp
            } for log in page_obj.object_list]

            return Response({
                "success": True,
                "data": log_data,
                "pagination": {
                    "total_pages": paginator.num_pages,
                    "current_page": page_number,
                    "total_items": paginator.count
                }
            })
        except Exception as e:
            logger.error(f"Audit log retrieval failed: {str(e)}")
            return Response({
                "success": False,
                "message": "Failed to retrieve audit logs"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)