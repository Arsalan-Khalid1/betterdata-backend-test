from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from .serializers import (
    ChangePasswordSerializer,
    PasswordResetSerializer,
    TokenObtainPairSerializer,
    UserSerializer,
    UserProfileUpdateSerializer,
)

User = get_user_model()


@api_view(['POST'])
def user_registration_view(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        user.is_active = False
        user.save()

        # Send email confirmation with activation link
        # ...

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def email_verification_view(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return Response({'detail': 'Email has been verified successfully.'})
    else:
        return Response(
            {'detail': 'Invalid verification link.'},
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(['POST'])
def password_reset_view(request):
    serializer = PasswordResetSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {'detail': 'No user with that email address.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        else:
            domain = request.get_host()
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_url = f'http://{domain}/reset-password/{uid}/{token}/'
            # TODO: send reset_url to user's email address
            return Response(
                {'detail': 'Password reset email sent.'},
                status=status.HTTP_200_OK,
            )
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def change_password_view(request, user_id):
    user = get_object_or_404(User, id=user_id)
    serializer = ChangePasswordSerializer(data=request.data)

    if serializer.is_valid():
        old_password = serializer.validated_data.get('old_password')
        new_password = serializer.validated_data.get('new_password')

        if not user.check_password(old_password):
            return Response(
                {'detail': 'Old password is not correct.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(new_password)
        user.save()
        return Response({'detail': 'Password updated successfully.'})

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_profile_view(request, user_id):
    user = get_object_or_404(User, id=user_id)

    # Check if the user is editing their own profile
    if user != request.user:
        return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

    serializer = UserProfileUpdateSerializer(instance=user, data=request.data)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def close_account_view(request, user_id):
    user = get_object_or_404(User, id=user_id)

    # Check if the user is deleting their own account
    if user != request.user:
        return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

    user.delete()
    return Response({'detail': 'Account deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    serializer = TokenObtainPairSerializer(data=request.data)
    if serializer.is_valid():
        return Response(serializer.validated_data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    # Since we are using JWT tokens, there is no need to perform any action on the server side to logout a user.
    # The client just needs to delete the access and refresh tokens.
    return Response({'detail': 'Successfully logged out.'}, status=status.HTTP_200_OK)
