from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.forms import  Textarea
from django.db import models

from .models import User, UserToken

class UserAdminConfig(UserAdmin):
    model = User
    search_fields = ('email', 'user_name', 'full_name',)
    readonly_fields = ['start_date']
    list_filter = ('is_active', 'is_staff', 'user_type')
    ordering = ('-start_date',)
    list_display = ('email', 'user_name', 'full_name','user_type',
                    'is_active', 'is_staff',)
    fieldsets = (
        ('Details', {'fields': ('email', 'user_name', 'full_name','user_type', 'password', 'start_date')}),
        ('Permissions', {'fields': ('is_staff', 'is_active' ,)}),
    )
    formfield_overrides = {
        models.TextField: {'widget': Textarea(attrs={'rows': 20, 'cols': 60})},
    }
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'user_name', 'full_name','user_type', 'password1', 'password2', 'is_active', 'is_staff',)}
         ),
    )
admin.site.register(User, UserAdminConfig)

@admin.register(UserToken)
class UserTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'last_activation_request')
    search_fields = ('user__email', 'user__user_name', 'user__full_name')