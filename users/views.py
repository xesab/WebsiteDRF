from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView

from .permissions import isManager,isActive
from .serializers import (ChangePasswordSerializer, CustomTokenObtainPairSerializer,
                          CustomUserSerializer)

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
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                json = serializer.data
                return Response(json, status=status.HTTP_201_CREATED)
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