import pyotp
from tabulate import tabulate
from datetime import datetime
import pandas as pd
import time
import getpass
import file_handler

def totp(secret_key):
    """
    Args:
        secret_key (string): secret in base64 format

    Returns:
        String: Current 30-second OTP
    """
    totp = pyotp.TOTP(secret_key)
    return totp.now()

def totp_offset(secret_key, offset=0):
    """
    Alternate method with offset time to see future OTP
    Doesn't work - gives a differring OTP
    """
    totp = pyotp.TOTP(secret_key)
    offset_time = int(time.time()) + offset
    return totp.generate_otp(offset_time)


if __name__ == "__main__":
    # attempt decrypt
    while True:
        password = getpass.getpass("Enter your password: ")
        tokens = file_handler.decrypt_file_with_password(password, "locked.bin")
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
            table.append([name, totp(secret)])
        
        time_elapsed = datetime.now().second % 30
        
        print(tabulate(table))
        time.sleep(30 - time_elapsed)
