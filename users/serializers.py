from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.forms import ValidationError
from rest_framework import serializers
from .models import User


class CustomUserSerializer(serializers.ModelSerializer):
    """
    Currently unused in preference of the below.
    """

    user_name = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    full_name = serializers.CharField(required=True)

    # new_password = serializers.CharField(min_length=8, write_only=True, required=True)

    class Meta:
        model = User
        fields = ('full_name','user_name','email', 'password', 'user_type')
        extra_kwargs = {'password': {'write_only': True}}

    def validate_email(self, value):
        """
        Check that the email is not already in use.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        return value
    
    def validate_user_name(self, value):
        """
        Check that the User name is not already in use.
        """
        if User.objects.filter(user_name=value).exists():
            raise serializers.ValidationError("A user with that username already exists.")
        return value
    
    def validate_password(self, value):
        """
        Apply Django's password validation rules.
        """
        user_data = self.initial_data
        user = User(
            email=user_data.get("email", ""),
            user_name=user_data.get("user_name", ""),
            full_name=user_data.get("full_name", "")
        )

        try:
            validate_password(value, user=user)  # Validate password against user attributes
        except DjangoValidationError as e:
            raise ValidationError(e.messages)  # Convert Django errors to DRF errors

        return value

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user_type = validated_data.pop('user_type', None)
        
        if user_type == 'admin':
            raise ValidationError(_('Really This is what you want to do ?'))
        # as long as the fields are the same, we can just use this
        instance = self.Meta.model(**validated_data)
        if password is not None:
            validated_data['password'] = make_password(password)
        return super().create(validated_data)
    
class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model.
    """
    class Meta:
        model = User
        fields = ('full_name', 'user_name','email','user_type',)
        read_only_fields = ('email','user_type',)
    

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['user_type'] = user.user_type
        return token

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _

User = get_user_model()

class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint with validation.
    """
    current_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True)

    def validate_current_password(self, value):
        """
        Check if the current password is correct.
        """
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(_("Current password is incorrect."))
        return value

    def validate_new_password(self, value):
        """
        Apply Django's password validation rules.
        """
        user = self.context['request'].user  # Get the current user

        try:
            validate_password(value, user=user)  # Validate against Django's rules
        except DjangoValidationError as e:
            raise ValidationError(e.messages)  # Convert Django errors to DRF errors

        return value