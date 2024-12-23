import yaml

def import_service(service:str, password:str) -> None:
    """Choose service to import secrets from and store them in locked.bin

    Args:
        service (str): type of service
        password (str): plaintext password to encrypt with
    """

def import_2fas(input_file:str) -> dict:
    """Function to parse exported 2fas csv's
    TODO: Decryption, figure out a schema (or just yoink 2fas')

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
        with open(input_file, 'r') as file:
            data = yaml.safe_load(file)
    except FileNotFoundError:
        raise FileNotFoundError

    try:
        services = data['services']
    except KeyError:
        raise KeyError
    except TypeError:
        raise TypeError

    return data


if __name__ == "__main__":
    filename = input("input file:")
    try:
        data = import_2fas(filename)
    except FileNotFoundError:
        print("file not found")
    print(data)
    ...
