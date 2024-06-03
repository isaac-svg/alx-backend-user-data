#!/usr/bin/env python3
"""
Definition of the Auth class
"""
from flask import request
from typing import (
    List,
    TypeVar
)


class Auth:
    """
    Manages the API authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines which route is protected
        Args:
            - path(str): route to be checked
            - excluded_paths(List of str): List of routes that are
            unprotected
              authentication
        Return:
            - True if route is not in excluded_paths, else False
        """
        if path is None:
            return True
        elif excluded_paths is None or excluded_paths == []:
            return True
        elif path in excluded_paths:
            return False
        else:
            for i in excluded_paths:
                if i.startswith(path):
                    return False
                if path.startswith(i):
                    return False
                if i[-1] == "*":
                    if path.startswith(i[:-1]):
                        return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Returns the authorization header from a request object
        """
        if request is None:
            return None
        header = request.headers.get('Authorization')
        if header is None:
            return None
        return header

    def current_user(self, request=None) -> TypeVar['User']:
        """
        Gets the user based on the information provided
        in the request header
        """
        return None
