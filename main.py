"""
Main runner to kick-off process

Currently is only CLI-based as I try to figure out code flow and logic before
fully using GUI

All print statements will eventually be replaced by either logging
statements or a GUI element
"""

import getpass
import time
from datetime import datetime

from tabulate import tabulate
from cryptography.fernet import InvalidToken

from file_utils import locked_handler
from totp.totp_generator import get_totp_offset


def cli_version():
    locked = True

    # first try default password
    try:
        secrets = locked_handler.decrypt_file_with_password()
        locked = False
    except InvalidToken:
        print("Default password didn't work")

    # attempt decrypt
    while locked:
        password = getpass.getpass("Enter your password: ")
        try:
            secrets = locked_handler.decrypt_file_with_password(password)
            locked = False
        except InvalidToken:
            print("Incorrect password\n")

    services = secrets['services']

    if secrets['secure_password'] == False:
        print("DEFAULT PASSWORD USED, USE SOMETHING ELSE")

    # displays OTP's
    while True:
        table = []

        for service in services:
            name = service['name']
            secret = service['secret']
            table.append([name,
                          get_totp_offset(secret),
                          get_totp_offset(secret, 30)
                          ])

        time_elapsed = datetime.now().second % 30

        print(tabulate(table))
        time.sleep(30 - time_elapsed)

if __name__ == "__main__":
    cli_version()
