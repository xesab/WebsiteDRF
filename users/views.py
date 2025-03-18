from django.forms import ValidationError
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView

from .permissions import isManager,isActive
from .serializers import (ChangePasswordSerializer, CustomTokenObtainPairSerializer,
                          CustomUserSerializer)
from .models import (User,)

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
                    return Response(json, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({'message':e}, status=status.HTTP_403_FORBIDDEN)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
            return Response({"detail": "Password updated successfully"}, status=status.HTTP_200_OK)
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
                return Response({'detail':'Really This is what you want to do ?'},status=status.HTTP_403_FORBIDDEN)
        if 'email' in request.data:
            return Response({'detail':'Email Updating Not Supported.'},status=status.HTTP_403_FORBIDDEN)
        if 'user_name' in request.data:
            return Response({'detail':'Username Updating Not Supported.'},status=status.HTTP_403_FORBIDDEN)
        serializer = CustomUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
