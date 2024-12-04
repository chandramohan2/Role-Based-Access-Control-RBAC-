from django.urls import path
from .views import UserManagementView, RoleManagementView, PermissionManagementView, AccessValidationView

urlpatterns = [
    path('users/', UserManagementView.as_view(), name='user-management'),
    path('roles/', RoleManagementView.as_view(), name='role-management'),
    path('permissions/', PermissionManagementView.as_view(), name='permission-management'),
    path('access/', AccessValidationView.as_view(), name='access-validation'),
]
