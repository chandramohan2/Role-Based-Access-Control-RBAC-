from django.urls import path
from .views import (
    create_user,
    assign_role,
    create_role,
    assign_permission_to_role,
    create_permission,
    validate_access,
)

urlpatterns = [
    path('create-user/', create_user, name='create_user'),
    path('assign-role/', assign_role, name='assign_role'),
    path('create-role/', create_role, name='create_role'),
    path('assign-permission-to-role/', assign_permission_to_role, name='assign_permission_to_role'),
    path('create-permission/', create_permission, name='create_permission'),
    path('validate-access/', validate_access, name='validate_access'),
]
