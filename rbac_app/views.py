from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User, Role, Permission, AuditLog
from .serializers import UserSerializer, RoleSerializer, PermissionSerializer, AuditLogSerializer


class UserManagementView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "success": True,
                "message": "User created successfully.",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "success": False,
            "message": "Invalid data.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response({"success": True, "data": serializer.data})


class RoleManagementView(APIView):
    def post(self, request):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "success": True,
                "message": "Role created successfully.",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "success": False,
            "message": "Invalid data.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True)
        return Response({"success": True, "data": serializer.data})


class PermissionManagementView(APIView):
    def post(self, request):
        serializer = PermissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "success": True,
                "message": "Permission created successfully.",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "success": False,
            "message": "Invalid data.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        permissions = Permission.objects.all()
        serializer = PermissionSerializer(permissions, many=True)
        return Response({"success": True, "data": serializer.data})


class AccessValidationView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        permission_name = request.data.get('permission_name')

        try:
            user = User.objects.get(_id=user_id)
            permission = Permission.objects.get(name=permission_name)

            # Check if the user has the permission
            has_permission = any(
                permission in role.permissions.all()
                for role in user.roles.all()
            )

            if has_permission:
                return Response({"success": True, "message": "Access granted."})
            else:
                return Response({"success": False, "message": "Access denied."}, status=status.HTTP_403_FORBIDDEN)

        except User.DoesNotExist:
            return Response({"success": False, "message": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        except Permission.DoesNotExist:
            return Response({"success": False, "message": "Permission not found."}, status=status.HTTP_404_NOT_FOUND)


class AuditLogView(APIView):
    def get(self, request):
        logs = AuditLog.objects.all()
        serializer = AuditLogSerializer(logs, many=True)
        return Response({"success": True, "data": serializer.data})
