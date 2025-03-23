from django.urls import path
from .views import *

app_name = 'User'

from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    path('login', login.as_view(), name='login'),
    path('get-access-token', TokenRefreshView.as_view(), name='get-access-token'),
    path('register', CustomUserCreate.as_view(), name="register-user"),
    path('logout', BlacklistTokenUpdateView.as_view(), name='blacklist' or 'logout'),
    path('change-password', ChangePasswordView.as_view(), name='change-password'),
    path('profile', ProfileView.as_view(),name = 'profile-view'),
    path('activate/<token>', ActivateAccount.as_view(), name='activate'),
]