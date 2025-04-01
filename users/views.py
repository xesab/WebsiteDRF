import jwt
from django.forms import ValidationError
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView

from .permissions import isActive
from .serializers import (ChangePasswordSerializer, CustomTokenObtainPairSerializer,
                          CustomUserSerializer)
from .models import (User,GeneratedToken)

from .mails import (sendActivationEmail,sendResetPasswordEmail,
                    decode_jwt_token,sendAccountDeletionEmail)

class CustomUserCreate(APIView):
    """
    Endpoint for creating a new user.
    """
    permission_classes = [AllowAny]

    def post(self, request, format='json'):
        """
        Saves a new user.

        Args:
            request: The request object containing user data.

        Returns:
            A Response object with the saved user data and a status code.
        """
        try:
            serializer = CustomUserSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                if user:
                    json = serializer.data
                    sendActivationEmail(request,user,json['email'])
                    return Response(json, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({'message':e}, status=status.HTTP_403_FORBIDDEN)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ActivateAccount(APIView):
    permission_classes = [AllowAny]

    def get(self, request, token):
        try:
            # Decode JWT token
            decoded_data = decode_jwt_token(token)
            user = User.objects.get(pk=decoded_data.get("user_id"))

            # Retrieve the token
            generated_token = GeneratedToken.objects.filter(user=user, token=token).first()
            if not generated_token:
                return Response({'message': 'Token has already been used or expired.'}, status=status.HTTP_400_BAD_REQUEST)

            if user.is_active:
                return Response({'message': 'Account already activated'}, status=status.HTTP_400_BAD_REQUEST)

            # Activate user
            user.is_active = True
            user.save()
            generated_token.delete()

            return Response({'message': 'Account Activated Successfully'}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({'message': 'Activation link has expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidTokenError:
            return Response({'message': 'Invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)


class BlacklistTokenUpdateView(APIView):
    """
    Endpoint for blacklisting a token.
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        """
        Blacklists a token.

        Args:
            request: The request object containing a refresh token.

        Returns:
            A Response object with a status code.
        """
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class login(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handles the POST request for logging in a user.
        """
        if 'email' not in request.data:
            return Response({'detail':'Email is required'},status=status.HTTP_400_BAD_REQUEST)
        if 'password' not in request.data:
            return Response({'detail':'Password is required'},status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.filter(email=request.data['email']).first()
        if user:
            if not user.is_active_user():
                return sendActivationEmail(request,user,user.email)
            if not user.check_password(request.data['password']):
                return Response({'detail':'Invalid password'},status=status.HTTP_400_BAD_REQUEST)
        
        serializer = CustomTokenObtainPairSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
   
class ChangePasswordView(APIView):
    """
    An endpoint for changing password.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Handles the POST request for changing the user's password.
        """
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProfileView(APIView):
    """
    Endpoint to Get Profile Information
    """
    permission_classes = [IsAuthenticated, isActive]

    def get(self, request, *args, **kwargs):
        """
        Handles the POST request for getting user profile data.
        """
        user = User.objects.get(id=request.user.id)
        serializer = CustomUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def patch(self, request):
        """
        Handles updating the user profile.
        """
        user = User.objects.get(id=request.user.id)
        user_type = request.data.get('user_type')
        if user_type:
            if user_type == 'admin':
                return Response({'message':'Really This is what you want to do ?'},status=status.HTTP_403_FORBIDDEN)
        if 'email' in request.data:
            return Response({'detail':'Email Updating Not Supported.'},status=status.HTTP_403_FORBIDDEN)
        if 'user_name' in request.data:
            return Response({'detail':'Username Updating Not Supported.'},status=status.HTTP_403_FORBIDDEN)
        serializer = CustomUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ForgotPassword(APIView):
    """
    Endpoint to handle forgot password request
    """

    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handle Post Request
        """
        if 'email' not in request.data:
            return Response({'detail': 'Provide email to reset password'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.filter(email=request.data['email']).first()
        if not user:
            return Response({'detail': 'If user is registered with this email, you will receive an email to reset password'}, status=status.HTTP_200_OK)
        sendResetPasswordEmail(request,user,user.email)
        return Response({'detail': 'If user is registered with this email, you will receive an email to reset password'}, status=status.HTTP_200_OK)

class ResetPassword(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get('token')
        password = request.data.get('password')

        if not password:
            return Response({'message': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Decode the JWT token
            decoded_data = decode_jwt_token(token)
            user = User.objects.get(pk=decoded_data.get("user_id"))

            # Validate token existence
            generated_token = GeneratedToken.objects.filter(user=user, token=token).first()
            if not generated_token:
                return Response({'message': 'Invalid reset password link'}, status=status.HTTP_400_BAD_REQUEST)

            if not user.is_active:
                return Response({'message': 'Account not activated'}, status=status.HTTP_400_BAD_REQUEST)

            # Update password and remove token
            user.set_password(password)
            user.save()
            generated_token.delete()

            return Response({'message': 'Password Reset Successfully'}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({'message': 'Reset password link has expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidTokenError:
            return Response({'message': 'Invalid reset password link'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
        
class RequestAccountDeletion(APIView):
    """
    Endpoint to handle account deletion
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Handle GET Request
        """
        user = request.user
        return sendAccountDeletionEmail(request, user, user.email)

class ConfirmAccountDeletion(APIView):
    """
    Endpoint to handle account deletion confirmation
    """

    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handle POST Request
        """
        try:
            # Decode JWT token
            token = request.data.get('token')
            if not token:
                return Response({'message': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)
            decoded_data = decode_jwt_token(token)
            user = User.objects.get(pk=decoded_data.get("user_id"))

            # Validate token existence
            generated_token = GeneratedToken.objects.filter(user=user, token=token).first()
            if not generated_token:
                return Response({'message': 'Invalid account deletion link'}, status=status.HTTP_400_BAD_REQUEST)

            # Delete user and token
            user.delete()
            generated_token.delete()

            return Response({'message': 'Account Deleted Successfully'}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({'message': 'Account deletion link has expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidTokenError:
            return Response({'message': 'Invalid account deletion link'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)