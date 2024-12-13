# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password
from .models import User, Permission, RolePermission, AuditLog

class UserListCreateView(APIView):
    def get(self, request):
        users = User.objects.all()
        users_data = [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'first_name': user.first_name,
            'last_name': user.last_name
        } for user in users]
        return Response(users_data)

    def post(self, request):
        if request.data.get('role') != User.Role.ADMIN:
            return Response(
                {'error': 'Only admin can create users'},
                status=status.HTTP_403_FORBIDDEN
            )

        data = request.data
        data['password'] = make_password(data.get('password'))

        try:
            user = User.objects.create(**data)
            return Response({
                'id': str(user.id),  # Convert ObjectId to string
                'username': user.username,
                'email': user.email,
                'role': user.role
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class UserDetailView(APIView):
    def get(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        return Response({
            'id': str(user.id),
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'first_name': user.first_name,
            'last_name': user.last_name
        })

    def put(self, request, user_id):
        if request.user.role != User.Role.ADMIN:
            return Response(
                {'error': 'Only admin can update users'},
                status=status.HTTP_403_FORBIDDEN
            )

        user = get_object_or_404(User, id=user_id)
        data = request.data

        for key, value in data.items():
            if key == 'password':
                value = make_password(value)
            setattr(user, key, value)

        user.save()
        return Response({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        })

    def delete(self, request, user_id):
        if request.user.role != User.Role.ADMIN:
            return Response(
                {'error': 'Only admin can delete users'},
                status=status.HTTP_403_FORBIDDEN
            )

        user = get_object_or_404(User, id=user_id)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class PermissionListCreateView(APIView):
    def get(self, request):
        permissions = Permission.objects.all()
        permissions_data = [{
            'id': perm.id,
            'name': perm.name,
            'codename': perm.codename,
            'description': perm.description
        } for perm in permissions]
        return Response(permissions_data)

    def post(self, request):
        # if request.data.get('role') != User.Role.ADMIN:
        #     return Response(
        #         {'error': 'Only admin can create permissions'},
        #         status=status.HTTP_403_FORBIDDEN
        #     )

        try:
            permission = Permission.objects.create(**request.data)
            return Response({
                'id': permission.id,
                'name': permission.name,
                'codename': permission.codename,
                'description': permission.description
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class RolePermissionListCreateView(APIView):
    def get(self, request):
        role_permissions = RolePermission.objects.all()
        data = [{
            'id': rp.id,
            'role': rp.role,
            'permission': {
                'id': rp.permission.id,
                'name': rp.permission.name,
                'codename': rp.permission.codename
            }
        } for rp in role_permissions]
        return Response(data)

    def post(self, request):
        # if request.user.role != User.Role.ADMIN:
        #     return Response(
        #         {'error': 'Only admin can assign permissions to roles'},
        #         status=status.HTTP_403_FORBIDDEN
        #     )

        try:
            role_perm = RolePermission.objects.create(
                role=request.data.get('role'),
                permission_id=request.data.get('permission_id')
            )
            return Response({
                'id': str(role_perm.id),
                'role': role_perm.role,
                'permission': {
                    'id': role_perm.permission.id,
                    'name': role_perm.permission.name
                }
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class ValidateAccessView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        permission_codename = request.data.get('permission')

        if not user_id or not permission_codename:
            return Response(
                {'error': 'Both user_id and permission are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = get_object_or_404(User, id= user_id)
        permission = get_object_or_404(Permission, codename=permission_codename)

        has_permission = (
            user.role == User.Role.ADMIN or
            RolePermission.objects.filter(
                role=user.role,
                permission=permission
            ).exists()
        )

        AuditLog.objects.create(
            user=user,
            action='permission_check',
            resource=permission.codename,
            success=has_permission,
            details=f"Checked permission: {permission.name}"
        )

        return Response({'has_permission': has_permission})

class AuditLogListView(APIView):
    def get(self, request):
        if request.user.role != User.Role.ADMIN:
            logs = AuditLog.objects.filter(user=request.user)
        else:
            logs = AuditLog.objects.all()

        logs = logs.order_by('-timestamp')
        logs_data = [{
            'id': log.id,
            'user': log.user.username,
            'action': log.action,
            'resource': log.resource,
            'timestamp': log.timestamp,
            'success': log.success,
            'details': log.details
        } for log in logs]

        return Response(logs_data)

