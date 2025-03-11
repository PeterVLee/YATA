"""
Maybe this doesn't need its own module and I honestly don't expect to
make implementations for stuff other than the standard TOTP but whatever
"""

import time

import pyotp

def get_totp_offset(secret_key:str, offset:int = 0) -> str:
    """Given a secret, return the TOTP

    Args:
        secret_key (str): secret in base64 format
        offset (int): offset to the future in seconds, defaults to 0

    Returns:
        str: OTP value
    """
    totp = pyotp.TOTP(secret_key)
    offset_time = int(time.time()) + offset
    return totp.at(offset_time)
