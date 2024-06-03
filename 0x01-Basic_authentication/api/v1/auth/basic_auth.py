#!/usr/bin/env python3
"""
Create a class BasicAuth that inherits from Auth
"""

from api.v1.auth.auth import Auth
from typing import Tuple, TypeVar
from models.user import User
import base64


class BasicAuth(Auth):
    """ BasicAuth class """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """Extracts the Base64 part of a Basic Authorization header."""

        if isinstance(authorization_header,
                      str) and authorization_header.startswith('Basic '):
            return authorization_header.split(' ', 1)[1]
        return None

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Decodes a Base64-encoded authorization header."""

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(
                    base64_authorization_header.encode('utf-8'))
            return decoded_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """Extracts user credentials from a decoded authorization header."""

        if not isinstance(decoded_base64_authorization_header, str
                          ) or ':' not in decoded_base64_authorization_header:
            return (None, None)

        email, passwd = decoded_base64_authorization_header.split(':', 1)
        return email, passwd

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Returns a User object based on provided credentials."""

        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None

        User.load_from_file()
        count = User.count()
        if not count:
            return None
        users = User.search({'email': user_email})
        if not users:
            return None
        user = users[0]
        if user.is_valid_password(user_pwd):
            return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns the current user based on the authorization header."""

        auth_header = self.authorization_header(request)
        credential = self.extract_base64_authorization_header(auth_header)
        plain_credential = self.decode_base64_authorization_header(credential)
        email, passwd = self.extract_user_credentials(plain_credential)
        user = self.user_object_from_credentials(email, passwd)
        print(user)

        return user
