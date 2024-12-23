import getpass
import time
from tabulate import tabulate
from datetime import datetime

import file_utils.locked_handler as locked_handler
from cryptography.fernet import InvalidToken
from totp.totp_generator import get_totp_offset


if __name__ == "__main__":

    # -------------------------------------------------------------------------------------------------
    # CLI version -------------------------------------------------------------------------------------
    # -------------------------------------------------------------------------------------------------

    # attempt decrypt
    while True:
        password = getpass.getpass("Enter your password: ")
        try:
            secrets = locked_handler.decrypt_file_with_password(password)
            break
        except InvalidToken:
            print("Incorrect password\n")

    services = secrets['services']

    # displays OTP's
    while True:
        table = []

        for service in services:
            name = service['name']
            secret = service['secret']
            table.append([name, get_totp_offset(secret)])

        time_elapsed = datetime.now().second % 30

        print(tabulate(table))
        time.sleep(30 - time_elapsed)

    # -------------------------------------------------------------------------------------------------
    # CLI version -------------------------------------------------------------------------------------
    # -------------------------------------------------------------------------------------------------
