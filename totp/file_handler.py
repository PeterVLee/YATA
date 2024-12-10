import os
import io
import base64

import pandas as pd

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key_from_password(password, salt=b''):
    """_summary_

    Args:
        password (string): Password for generated base64encode
        salt (bytes, optional): _description_. Defaults to b''.

    Returns:
        _type_: base64encode generated from password
    """
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
                            output_file:str,
                            password:str,
                            delete_input:bool = False):
    """Takes an input file path and encrypts it with the chosen password, saved to the chosen output path.

    Args:
        input_file (str): Path to the input file
        output_file (str): Path to the encrypted output file
        password (str): Chosen plain-text password
        delete_input (bool, optional): If True, Delete the original file. Defaults to False.
    """
    # TODO exception handling for stuff like FileNotFound

    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)

    with open(input_file, 'rb') as f:
        data = f.read()

    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data)

    with open(output_file, 'wb') as f:
        f.write(salt + encrypted_data)

def decrypt_file_with_password(password:str, input_file:str) -> pd.DataFrame:
    """Attempts to decrypt the secrets file and load it into memory as a dataframe

    Args:
        password (string): Password to attempt unlock
        input_file (string): Path to locked file

    Returns:
        DataFrame: A populated dataframe upon successful unlock; empty dataframe if unsuccessful
    """
    with open(input_file, 'rb') as f:
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

if __name__ == "__main__":
    print()