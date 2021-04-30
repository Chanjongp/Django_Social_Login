from rest_framework_simplejwt.views import TokenViewBase
from .serializers import CustomTokenRefreshSerializer


class CustomTokenRefreshView(TokenViewBase):
    """
    Takes a refresh type JSON web token and returns an access type JSON web
    token if the refresh token is valid.
    """
    serializer_class = CustomTokenRefreshSerializer
