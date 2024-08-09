#!/usr/bin/env python3
"""
Module for authentication
"""
import os
from typing import List, TypeVar

from flask import request


class Auth():
    """Template for all authentication system implemented in this app.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Takes a path and a list of excluded paths as arguments
        and returns a boolean value.
        """
        if not path or not excluded_paths:
            return True
        check = path.rstrip("/")
        for excluded_path in excluded_paths:
            if excluded_path.endswith("*") and \
                    check.startswith(excluded_path[:-1]):
                return False
            elif check == excluded_path.rstrip("/"):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Gets the value of the Authorization header from the request
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Takes a request object as an optional argument and returns a value
        of type 'User'.
        """
        return None

    def session_cookie(self, request=None) -> str:
        """Retrieves the session cookie from a request."""
        if request is not None:
            cookie_name = os.getenv('SESSION_NAME')
            return request.cookies.get(cookie_name)
