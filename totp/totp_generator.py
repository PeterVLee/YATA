import pyotp
from tabulate import tabulate
from datetime import datetime
import pandas as pd
import time
import getpass
import file_utils.locked_handler as locked_handler

def get_totp(secret_key):
    """Given a secret, return the TOTP

    Args:
        secret_key (string): secret in base64 format

    Returns:
        String: Current 30-second OTP
    """
    totp = pyotp.TOTP(secret_key)
    return totp.now()

def get_totp_30s_offset(secret_key, offset:int = 0):
    """
    Alternate method with 30 second offset time to see future OTP
    !!DOESN'T WORK!!
    Args:
        secret_key (string): secret in base64 format
        offset (int): offset to the future in seconds, defaults to 0
    """
    totp = pyotp.TOTP(secret_key)
    offset_time = int(time.time()) + offset
    return totp.generate_otp(offset_time)


if __name__ == "__main__":
    # attempt decrypt
    while True:
        password = getpass.getpass("Enter your password: ")
        tokens = locked_handler.decrypt_file_with_password(password)
        if tokens.empty == False:
            break
        else:
            print("Incorrect password\n")

    # displays OTP's
    while True:
        table = []

        for index in tokens.index:
            name = tokens['name'][index]
            secret = tokens['secret'][index]
            table.append([name, get_totp(secret)])

        time_elapsed = datetime.now().second % 30

        print(tabulate(table))
        time.sleep(30 - time_elapsed)
