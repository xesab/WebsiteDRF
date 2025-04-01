from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import send_mail
from rest_framework.response import Response
from rest_framework import status

import jwt
from website import settings
from datetime import datetime, timedelta

from .models import GeneratedToken

def generate_activation_token(user):
    """
    Generates a JWT token with an expiration time for account activation.
    """
    expiration_time = datetime.now() + timedelta(minutes=20)  # Token valid for 20 minutes
    payload = {
            "user_id": user.id,
            "exp": expiration_time.timestamp(),  # Expiration time
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ENCRYPT_ALGORITHM)  # Generate JWT token
    # Delete any existing token for the user
    GeneratedToken.objects.filter(user=user).delete()
    GeneratedToken.objects.create(user=user, token=token)
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
            'token' : token,
        })

        send_mail(
            subject="Confirm your email",
            message=f"Click the link to activate your account: {activation_link}",  # Fallback plain text
            from_email=settings.DEFAULT_FROM_EMAIL,
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
    
def sendResetPasswordEmail(request, user, to_email):
    """
    Sends an account activation email with an HTML template.
    """
    if user.can_get_reset_password_link():
        domain = get_current_site(request).domain
        protocol = "https" if request.is_secure() else "http"  # Auto-detect HTTP or HTTPS
        token = generate_activation_token(user)
        reset_password_link = f"{protocol}://{domain}/reset-password/{token}"

        html_message = render_to_string('reset_password_email.html', {
            'user': user,
            'reset_password_link': reset_password_link,
            'domain': domain,
            'token': token,
        })

        send_mail(
            subject="Reset your password",
            message=f"Click the link to reset your password: {reset_password_link}",  # Fallback plain text
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to_email],
            fail_silently=False,
            html_message=html_message,  # HTML email support
        )

        # Update user's last activation link time
        user.last_password_reset = datetime.now()
        user.save()

        return Response({'message': 'Reset password link sent'}, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'Reset password link already sent. Check mail and validate Email to continue'}, status=status.HTTP_400_BAD_REQUEST)
    
def sendAccountDeletionEmail(request, user, to_email):
    """
    Sends an account deletion email with an HTML template.
    """
    if user.can_get_delete_account_link():
        # Generate the account deletion link
        domain = get_current_site(request).domain
        protocol = "https" if request.is_secure() else "http"  # Auto-detect HTTP or HTTPS
        token = generate_activation_token(user)
        account_deletion_link = f"{protocol}://{domain}/delete-account/{token}"

        html_message = render_to_string('account_deletion_email.html', {
            'user': user,
            'account_deletion_link': account_deletion_link,
            'domain': domain,
            'token': token,
        })

        send_mail(
            subject="Delete your account",
            message=f"Click the link to delete your account: {account_deletion_link}",  # Fallback plain text
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to_email],
            fail_silently=False,
            html_message=html_message,  # HTML email support
        )
        user.last_delete_request = datetime.now()
        user.save()
        return Response({'message': 'Account deletion link sent'}, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'Account deletion link already sent. Check mail and validate Email to continue'}, status=status.HTTP_400_BAD_REQUEST)

def decode_jwt_token(token):
    """
    Decodes a JWT token and returns the payload.
    """
    return jwt.decode(token, settings.SECRET_KEY, algorithms=settings.ENCRYPT_ALGORITHM)