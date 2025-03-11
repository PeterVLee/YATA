"""
Handles services + secrets dictionary
"""

def switch_service_places(services: list, index1: int, index2: int) -> list:
    """Switches the places of two services in the list

    Args:
        services (list): List of services taken from secrets dict
        index1 (int): first target index
        index2 (int): second target index

    Returns:
        list: Same list with switched indices
    """

    temp = services[index1]
    services[index1] = services[index2]
    services[index2] = temp

    return services

def add_service(services: list, name: str, secret: str, index: int = None) -> list:
    """Adds a service to the list

    Args:
        services (list): List of services taken from secrets dict
        name (str): name of service
        secret (str): OTP key
        index (int, optional): Index to insert service. Defaults to None.

    Returns:
        list: Same list with service inserted
    """

    