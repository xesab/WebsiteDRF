import jwt
from django.forms import ValidationError
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import send_mail


from website.settings.base import SECRET_KEY, DEFAULT_FROM_EMAIL

from .permissions import isManager,isActive
from datetime import datetime, timedelta
from .serializers import (ChangePasswordSerializer, CustomTokenObtainPairSerializer,
                          CustomUserSerializer)
from .models import (User)

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

def generate_activation_token(user):
    """
    Generates a JWT token with an expiration time for account activation.
    """
    expiration_time = datetime.now() + timedelta(minutes=20)  # Token valid for 20 minutes
    payload = {
            "user_id": user.id,
            "exp": expiration_time.timestamp(),  # Expiration time
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")  # Generate JWT token
    return token

def sendActivationEmail(request, user, to_email):
    """
    Sends an account activation email with an HTML template.
    """
    if user.can_get_new_activation_link():
        domain = get_current_site(request).domain
        protocol = "https" if request.is_secure() else "http"  # Auto-detect HTTP or HTTPS
        token = generate_activation_token(user)
        activation_link = f"{protocol}://{domain}/activate/{token}"

        html_message = render_to_string('activation_email.html', {
            'user': user,
            'activation_link': activation_link,
            'domain': domain,
        })

        send_mail(
            subject="Confirm your email",
            message=f"Click the link to activate your account: {activation_link}",  # Fallback plain text
            from_email=DEFAULT_FROM_EMAIL,
            recipient_list=[to_email],
            fail_silently=False,
            html_message=html_message,  # HTML email support
        )

        # Update user's last activation link time
        user.last_activation_link = datetime.now()
        user.save()

        return Response({'message': 'Activation link sent'}, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'Activation link already sent. Check mail and validate Email to continue'}, status=status.HTTP_400_BAD_REQUEST)
    
class ActivateAccount(APIView):
    permission_classes = [AllowAny]

    def get(self, request, token):
        try:
            # Decode the JWT token
            decoded_data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_data.get("user_id")

            # Check if user exists
            user = User.objects.get(pk=user_id)
            if user:
                if user.is_active:
                    return Response({'message': 'Account already activated'}, status=status.HTTP_400_BAD_REQUEST)
                user.is_active = True
                user.save()
                return Response({'message': 'Account Activated Successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'Invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)

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

class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Endpoint for obtaining a token pair.
    """
    serializer_class = CustomTokenObtainPairSerializer

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
    permission_classes = [IsAuthenticated,isActive]

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
