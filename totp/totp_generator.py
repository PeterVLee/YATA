"""
Maybe this doesn't need its own module and I honestly don't expect to
make implementations for stuff other than the standard TOTP but whatever
"""

import pyotp
import pandas as pd
import time

def get_totp_offset(secret_key:str, offset:int = 0) -> str:
    """Given a secret, return the TOTP
    Args:
        secret_key (str): secret in base64 format
        offset (int): offset to the future in seconds, defaults to 0

    Returns:
        str: offset OTP
    """
    totp = pyotp.TOTP(secret_key)
    offset_time = int(time.time()) + offset
    return totp.at(offset_time)


if __name__ == "__main__":
    import getpass
    from tabulate import tabulate
    from datetime import datetime
    import file_utils.locked_handler as locked_handler

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
            table.append([name, get_totp_offset(secret)])

        time_elapsed = datetime.now().second % 30

        print(tabulate(table))
        time.sleep(30 - time_elapsed)
