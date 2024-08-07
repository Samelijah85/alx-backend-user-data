#!/usr/bin/env python3
"""
Basic Auth module
"""

from api.v1.auth.auth import Auth
from typing import TypeVar, List
from models.user import User
import base64
import binascii


class BasicAuth(Auth):
    """
    class BasicAuth
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
         returns the Base64 part of the Authorization
         header for a Basic Authentication
        """
        if (authorization_header is None or
                not isinstance(authorization_header, str) or
                not authorization_header.startswith("Basic")):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        returns the decoded value of a Base64
        string base64_authorization_header
        """
        b64_auth_header = base64_authorization_header
        if b64_auth_header and isinstance(b64_auth_header, str):
            try:
                encode = b64_auth_header.encode('utf-8')
                base = base64.b64decode(encode)
                return base.decode('utf-8')
            except binascii.Error:
                return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
        returns the user email and password from the Base64 decoded value.
        """
        decoded_64 = decoded_base64_authorization_header
        if (decoded_64 and isinstance(decoded_64, str) and
                ":" in decoded_64):
            res = decoded_64.split(":", 1)
            return (res[0], res[1])
        return (None, None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        overloads Auth and retrieves the User instance for a request
        """
        header = self.authorization_header(request)
        b64header = self.extract_base64_authorization_header(header)
        decoded = self.decode_base64_authorization_header(b64header)
        user_creds = self.extract_user_credentials(decoded)
        return self.user_object_from_credentials(*user_creds)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        Returns the User instance based on the email and password.
        """
        if not all(map(lambda x: isinstance(x, str), (user_email, user_pwd))):
            return None
        try:
            user_data = User.search(attributes={'email': user_email})
        except Exception as e:
            return None
        if not user_data:
            return None
        user = user_data[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user
