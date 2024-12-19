"""
File IO module. Uses hazmat libraries that I have no full knowledge of.

Uses the ~/.yata/ directory to store files
"""

import os
import io
import base64

# TODO: replace pandas with yaml or json
import pandas as pd

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
# TODO: Either stop using hazmat libraries or draw 25 and take a course on cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Main directory for local storage
YATA_DIRECTORY = os.path.expanduser('~') + '/.yata/'
LOCKED_FILE = YATA_DIRECTORY + 'locked.bin'

def generate_key_from_password(password, salt=b''):
    """Encodes a password into base64

    Args:
        password (string): Password for generated base64encode
        salt (bytes, optional): _description_. Defaults to b''.

    Returns:
        _type_: base64encode generated from password
    """
    # I have no idea what this shit is doing, seriously need to stop using the hazmat stuff
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_file_with_password(input_file:str,
                            password:str,
                            delete_input:bool = False):
    """Takes an input file path and encrypts it with the chosen password, saved to locked.bin in .yata

    Make sure the user wants to overwrite locked.bin if it already exists

    Args:
        input_file (str): Path to the input file
        password (str): Chosen plain-text password
        delete_input (bool, optional): If True, Delete the original file. Defaults to False.
    """
    # TODO exception handling for stuff like FileNotFound

    check_if_exists(YATA_DIRECTORY)

    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)

    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except FileNotFoundError as err:
        raise err

    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data)

    with open(LOCKED_FILE, 'wb') as f:
        f.write(salt + encrypted_data)

def decrypt_file_with_password(password:str) -> pd.DataFrame:
    """Attempts to decrypt the secrets file and load it as a dataframe

    Args:
        password (string): Password to attempt unlock

    Returns:
        DataFrame: A populated dataframe upon successful unlock; empty dataframe if unsuccessful
    """

    if not check_if_exists(YATA_DIRECTORY):
        raise FileNotFoundError

    with open(LOCKED_FILE, 'rb') as f:
        salt = f.read(16)
        encrypted_data = f.read()

    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        file_like = io.BytesIO(decrypted_data)
        df = pd.read_csv(file_like)
    except InvalidToken:
        df = pd.DataFrame()
    return df

def check_if_exists(directory: str) -> bool:
    """ Create a directory if needed.

    Args:
        directory (str): Path to directory to check/create

    Returns:
        bool: Returns True if the directory existed, False if one had to be created
    """
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
            return False
    except PermissionError:
        raise
    return True

if __name__ == "__main__":
    print()
