import pyotp
import csv
from tabulate import tabulate
from datetime import datetime
import pandas as pd
import time

import file_handler
import service_importer

def totp(secret_key):
    """
    Basic TOTP function
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

while True:
    password = input("Enter your password: ")
    tokens = file_handler.decrypt_file_with_password(password, "locked.bin")
    if tokens.empty == False:
        break
    else:
        print("Incorrect password\n")

table = []

for index in tokens.index:
    name = tokens['name'][index]
    secret = tokens['secret'][index]
    table.append([name, totp(secret)])

print(tabulate(table))
print(str(datetime.now().second % 30) + " / 30")