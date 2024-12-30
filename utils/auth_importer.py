"""
This module is responsible for importing secrets from various authentication apps
"""
import os

import yaml

from locked_handler import update_secrets_file

# TODO: Move to a config file
YATA_DIRECTORY = os.path.expanduser('~/.yata/')
LOCKED_FILE = YATA_DIRECTORY + 'locked.bin'
UNSECURE_FILE = YATA_DIRECTORY + 'unsecure_secrets.yaml'

def import_authenticator(auth_type:str, file_path:str, password:str) -> None:
    """Choose auth app to import secrets from and store them in locked.bin

    # TODO: Remove need for auth_type and determine it from file_path
    # some regex is probably needed for this (ugh)

    # TODO: Check if file exists. If it does, add to it rather than overwrite it

    Args:
        auth_type (str): type of auth app
        file_path (str): path to file exported from auth app
        password (str): plaintext password to encrypt with
    """

    secrets = {}

    # I don't like using strings like this but whatever
    match auth_type:
        case "2fas":
            secrets = __import_2fas(file_path)
        # these are placeholders
        case "lastpass":
            ...
        case "keepass":
            ...
        case "bitwarden":
            ...
        case "1password":
            ...

    update_secrets_file(secrets, password)

def __import_2fas(input_file:str) -> dict:
    """2fas file parser

    TODO: Decryption from password, figure out a schema (or just yoink 2fas')

    Args:
        input_file (str): Path to csv

    Returns:
        dict: Parsed names and secrets

    Raises:
        FileNotFoundError: Bad input link
        KeyError: File is in json/yaml format but likely isn't 2fas
        TypeError: File isn't json/yaml format
    """

    try:
        with open(input_file, 'r', encoding='UTF-8') as file:
            data = yaml.safe_load(file)

        # not doing anything with services, just checking if it parses right
        services = data['services']

    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {input_file}")
    except KeyError:
        raise KeyError(f"File likely isn't 2fas")
    except TypeError:
        raise TypeError(f"File isn't json/yaml format")

    return data


if __name__ == "__main__":
    filename = input("input file:")
    password = input("password:")
    #try:
        #import_data = __import_2fas(filename)
    #except FileNotFoundError:
        #print("file not found")
    #print(import_data)
    import_authenticator("2fas", filename, password)
    print()
