#!/usr/bin/env python3
"""Encrypting passwords and  Check valid password"""

import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    Args:
        password (str): password
    Returns:
        password
    """
    encoded_pass = password.encode()
    hashed_pass = hashpw(encoded_pass, bcrypt.gensalt())

    return hashed_pass


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check whether a password is valid
    Args:
        hashed_password (bytes): hashed password
        password (str): password
    Return:
        bool
    """
    valid = bcrypt.checkpw(password.encode(), hashed_password)

    return valid