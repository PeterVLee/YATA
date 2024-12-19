import yaml

def import_2fas(input_file:str) -> dict:
    """Function to parse exported 2fas csv's
    TODO: Decryption, figure out a schema (or just yoink 2fas')

    Args:
        input_file (str): Path to csv

    Returns:
        dict: Parsed names and secrets
    """
    with open(input_file, 'r') as file:
        data = yaml.safe_load(file)

    return data['services']

if __name__ == "__main__":
    ...
