from django.http import JsonResponse
import json
from .models import *

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import User
import json


@csrf_exempt
def create_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')

        if not username or not password:
            return JsonResponse({"success": False, "message": "Username and password are required"})

        if User.objects.filter(username=username).exists():
            return JsonResponse({"success": False, "message": "Username already exists"})

        user = User.objects.create(username=username, password=password, email=email)
        return JsonResponse({"success": True, "message": "User created successfully", "data": {"username": user.username}})

from .models import Role


@csrf_exempt
def assign_role(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        role_name = data.get('role')

        try:
            user = User.objects.get(username=username)
            role = Role.objects.get(name=role_name)
            user.roles.add(role)
            return JsonResponse({"success": True, "message": f"Role {role_name} assigned to {username}"})
        except User.DoesNotExist:
            return JsonResponse({"success": False, "message": "User not found"})
        except Role.DoesNotExist:
            return JsonResponse({"success": False, "message": "Role not found"})


@csrf_exempt
def create_role(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        role_name = data.get('role_name')

        if not role_name:
            return JsonResponse({"success": False, "message": "Role name is required"})

        role, created = Role.objects.get_or_create(name=role_name)
        if created:
            return JsonResponse({"success": True, "message": "Role created successfully"})
        else:
            return JsonResponse({"success": False, "message": "Role already exists"})


from .models import Permission


@csrf_exempt
def assign_permission_to_role(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        role_name = data.get('role_name')
        permission_name = data.get('permission_name')

        try:
            role = Role.objects.get(name=role_name)
            permission = Permission.objects.get(name=permission_name)
            role.permissions.add(permission)
            return JsonResponse({"success": True, "message": f"Permission {permission_name} assigned to role {role_name}"})
        except Role.DoesNotExist:
            return JsonResponse({"success": False, "message": "Role not found"})
        except Permission.DoesNotExist:
            return JsonResponse({"success": False, "message": "Permission not found"})


@csrf_exempt
def create_permission(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        name = data.get('name')
        resource = data.get('resource')
        action = data.get('action')

        if not all([name, resource, action]):
            return JsonResponse({"success": False, "message": "All fields are required"})

        permission, created = Permission.objects.get_or_create(name=name, resource=resource, action=action)
        if created:
            return JsonResponse({"success": True, "message": "Permission created successfully"})
        else:
            return JsonResponse({"success": False, "message": "Permission already exists"})

@csrf_exempt
def validate_access(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        resource = data.get('resource')
        action = data.get('action')

        try:
            user = User.objects.get(username=username)
            permissions = Permission.objects.filter(roles__users=user, resource=resource, action=action)
            if permissions.exists():
                outcome = "Success"
                return JsonResponse({"success": True, "message": "Access granted"})
            else:
                outcome = "Failure"
                return JsonResponse({"success": False, "message": "Access denied"})
        finally:
            AuditLog.objects.create(user=user, resource=resource, action=action, outcome=outcome)

