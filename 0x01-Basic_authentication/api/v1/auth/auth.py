#!/usr/bin/env python3
""" Authentication Module
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """Auth class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """_summary_

        Args:
                path (str): _description_
                excluded_paths (List[str]): _description_

        Returns:
                bool: _description_
        """
        if path is None:
            return True

        if excluded_paths is None or excluded_paths == []:
            return True

        if path in excluded_paths:
            return False

        for excluded_path in excluded_paths:
            if excluded_path.startswith(path):
                return False
            elif path.startswith(excluded_path):
                return False
            elif excluded_path[-1] == "*":
                if path.startswith(excluded_path[:-1]):
                    return False

        return True

    def authorization_header(self, request=None) -> str:
        """_summary_

        Args:
            request ([type], optional): _description_. Defaults to None.

        Returns:
            str: _description_
        """
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """_summary_

        Args:
            request ([type], optional): _description_. Defaults to None.

        Returns:
            TypeVar('User'): _description_
        """
        return None

    def session_cookie(self, request=None):
        """_summary_

        Args:
            request ([type], optional): _description_. Defaults to None.

        Returns:
            _type_: _description_
        """
        if request is None:
            return None
        return request.cookies.get('session_id')