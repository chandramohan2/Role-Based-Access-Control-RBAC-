from rest_framework.views import APIView
from rest_framework.response import Response
from .models import User, Role, Permission, AuditLog
from .serializers import UserSerializer, RoleSerializer, PermissionSerializer, AuditLogSerializer

class UserManagementView(APIView):

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"success": True, "message": "User created", "data": serializer.data})
        return Response({"success": False, "message": serializer.errors})

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response({"success": True, "data": serializer.data})

class RoleManagementView(APIView):

    def post(self, request):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"success": True, "message": "Role created", "data": serializer.data})
        return Response({"success": False, "message": serializer.errors})

class PermissionManagementView(APIView):

    def post(self, request):
        serializer = PermissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"success": True, "message": "Permission created", "data": serializer.data})
        return Response({"success": False, "message": serializer.errors})

class AccessValidationView(APIView):

    def post(self, request):
        user = User.objects.get(id=request.data.get("user_id"))
        permission = Permission.objects.get(id=request.data.get("permission_id"))

        has_permission = False
        for role in user.roles.all():
            if permission in role.permissions.all():
                has_permission = True
                break

        AuditLog.objects.create(
            user=user,
            resource=permission.resource,
            action=permission.action,
            outcome="granted" if has_permission else "denied",
        )

        if has_permission:
            return Response({"success": True, "message": "Access granted"})
        return Response({"success": False, "message": "Access denied"})
