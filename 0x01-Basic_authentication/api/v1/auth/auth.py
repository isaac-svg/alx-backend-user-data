#!/usr/bin/env python3
"""
Module to manage the API authentication.
"""
from flask import abort, request
from typing import List, TypeVar
from models.user import User
import re


class Auth:
    """ Auth class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Determines if the given path requires authentication
        """
        if path is None or not excluded_paths:
            return True

        if path[-1] != '/':
            path = path + '/'
        for excluded_path in excluded_paths:
            if excluded_path[-1] == '*':
                excluded_path = excluded_path[:-1] + '.*'
            if re.fullmatch(excluded_path, path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """ Returns the authorization header from the request.
        """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """ Returns the current user. """
        return None
