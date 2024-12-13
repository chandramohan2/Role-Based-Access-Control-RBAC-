from django.urls import path
from .views import (
    UserListCreateView, UserDetailView,
    PermissionListCreateView, RolePermissionListCreateView,
    ValidateAccessView, AuditLogListView
)

urlpatterns = [
    # User Management URLs
    path('users/', UserListCreateView.as_view(), name='user-list-create'),
    path('users/<int:user_id>/', UserDetailView.as_view(), name='user-detail'),
    
    # Permission Management URLs
    path('permissions/', PermissionListCreateView.as_view(), name='permission-list-create'),
    
    # Role Permission Management URLs
    path('role-permissions/', RolePermissionListCreateView.as_view(), name='role-permission-list-create'),
    
    # Access Validation URL
    path('validate-access/', ValidateAccessView.as_view(), name='validate-access'),
    
    # Audit Log URL
    path('audit-logs/', AuditLogListView.as_view(), name='audit-log-list'),
]