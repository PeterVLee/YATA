"""
File IO module to handle locked.bin secrets file.

Uses hazmat libraries that I have no full knowledge of.

Uses the ~/.yata/ directory to store locked.bin
"""

import os
import io
import base64
import yaml

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
# TODO: Either stop using hazmat libraries or draw 25 and take a course on cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Main directory for local storage
YATA_DIRECTORY = os.path.expanduser('~') + '/.yata/'
LOCKED_FILE = YATA_DIRECTORY + 'locked.bin'
# If the user chooses not to set a password for ease of access, use this
# "password" to lock the file, but since this is open source it really
# isn't secure and there should be UI warnings telling them to set it
DEFAULT_PASSWORD = "uQjPMbGEa6D2u9"

def generate_key_from_password(password, salt=b''):
    """Encodes a password into base64 (I think)

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

def encrypt_file_with_password(input_file:str, password:str, delete:bool = False):
    """Takes an input file path and encrypts it with the chosen password

    Saved to locked.bin in ~/.yata/ directory.

    If there is no input i.e. `password == ""` then an unsafe, default
    password will be chosen.

    Make sure the user wants to overwrite locked.bin if it already exists

    Args:
        input_file (str): Path to the input file
        password (str): Chosen plain-text password
        delete (bool): Delete the input_file after. Defaults to False
    """
    if password == "":
        password = DEFAULT_PASSWORD
        print("Warning, non-secure password used")

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

def decrypt_file_with_password(password:str) -> dict:
    """Get stored .yaml data from locked.bin file

    Attempts to unlock with the chosen password first, then the default.

    TODO: If the default password works then send a warning somehow,
    maybe add another key in the dictionary like "secure_file": False/True

    Args:
        password (string): Password to attempt unlock

    Returns:
        dict: secrets

    Raises:
        FileNotFoundError: /.yata/ or locked.bin does not exist
        InvalidToken: Wrong password
    """
    is_secrets_secure = True

    try:
        file_stream = decrypt_file_stream(password)
    except InvalidToken:
        # inputted password didn't work, check default
        # this is probably bad practice
        try:
            file_stream = decrypt_file_stream(DEFAULT_PASSWORD)
            is_secrets_secure = False
        except InvalidToken:
            raise InvalidToken

    secrets_yaml = yaml.safe_load(file_stream)
    secrets_yaml['secure'] = is_secrets_secure

    return secrets_yaml

def decrypt_file_stream(password:str) -> io.BytesIO:
    """Attempt to decrypt file, mostly a helper function to decrypt_file_with_password

    Args:
        password (str): plaintext password

    Returns:
        io.BytesIO: file-like stream

    Raises:
        InvalidToken: Wrong password
    """
    with open(LOCKED_FILE, 'rb') as f:
        salt = f.read(16)
        encrypted_data = f.read()

    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        file_like = io.BytesIO(decrypted_data)
    except InvalidToken:
        raise InvalidToken

    return file_like


if __name__ == "__main__":
    input_password = input("password: ")
    secrets = decrypt_file_with_password(input_password)
    print()
