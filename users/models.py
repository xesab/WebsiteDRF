from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager

class CustomAccountManager(BaseUserManager):

    def create_superuser(self, email, user_name, password, **other_fields):
        user_type = 'admin'
        full_name = 'admin'
        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_active', True)

        if other_fields.get('is_staff') is not True:
            raise ValueError('Superuser must be assigned to is_staff=True.')
        if other_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must be assigned to is_superuser=True.')

        return self.create_user(email, user_name,full_name, user_type, password, **other_fields)

    def create_user(self, email, user_name, full_name, user_type, password, **other_fields):

        if not email:
            raise ValueError(_('You must provide an email address'))

        email = self.normalize_email(email)
        user = self.model(email=email, user_name=user_name,
                          full_name=full_name, user_type=user_type, **other_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    USER_TYPE_CHOICES = [
        ('admin', 'admin'),
        ('staff', 'staff'),
        ('user', 'user'),
    ]
    email = models.EmailField(_('email address'), unique=True)
    user_name = models.CharField(max_length=150, unique=True)
    full_name = models.CharField(max_length=150)
    user_type = models.CharField(max_length=50, choices=USER_TYPE_CHOICES, default="user")
    start_date = models.DateTimeField(default=timezone.now,editable=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)  # Default to False

    last_activation_link = models.DateTimeField(null=True, blank=True)
    last_password_reset = models.DateTimeField(null=True, blank=True)

    objects = CustomAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['user_name']

    def __str__(self):
        return self.user_name
    
    def is_active_user(self):
        return self.is_active
    
    def can_get_new_activation_link(self):
        if self.last_activation_link is None:
            return True
        time_difference = timezone.now() - self.last_activation_link
        if time_difference.total_seconds() // 60 >= 30:
            return True
        return False
    def can_get_reset_password_link(self):
        if self.last_password_reset is None:
            return True
        time_difference = timezone.now() - self.last_password_reset
        if time_difference.total_seconds() // 60 >= 30:
            return True
        return False

class GeneratedToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255)

    class Meta:
        verbose_name = 'Generated Token'
        verbose_name_plural = 'Generated Tokens'
    
    def __str__(self):
        return self.user.user_name