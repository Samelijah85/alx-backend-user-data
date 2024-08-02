#!/usr/bin/env python3
"""
Module encrypt_password

Encrypting passwords
"""


import bcrypt


def hash_password(password: str) -> bytes:
    """
    A function that generates a salted hash of the input password.

    Parameters:
        - password: a string representing the password to be hashed.

    Returns:
        A bytes object representing the salted hash of the input password.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    A function that checks if a password is valid by comparing it with a
    hashed password.

    Parameters:
        - hashed_password: a bytes object representing the hashed password
        to compare.
        - password: a string representing the password to check.

    Returns:
        A boolean indicating whether the password is valid.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
