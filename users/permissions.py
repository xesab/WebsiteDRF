from rest_framework.permissions import BasePermission

class isManager(BasePermission):
    message = "Only Manager can perform this action"
    def has_permission(self, request, view):
        return request.user.user_type == 'Manager'

class isActive(BasePermission):
    message = "Only Active user can perform this action"
    def has_permission(self, request, view):
        return request.user.is_active
