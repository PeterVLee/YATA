"""
Handles services + secrets dictionary by modifying groups and ordering

Follows 2fas' schema, which works like the following:

* `groups`: defines named folders for services to fall in to.
    * [i] - index of the group
        * ['id'] - unique id for group
        * (unused) ['isExpanded'] - says whether group is expanded
        * ['name'] - user-defined name for group
        * (unused) ['updatedAt'] - date in unix the group was updated

* `services`: defines the actual 2FA secrets.
    * [i] - index of the service
        * ['groupId'] - id of the group to shove this under
        * (unused) ['icon'] - info on icon to use for service
        * ['name'] - user-defined name for service
        * ['order']['position'] - also the index of the service
            * not sure why this is used here when the first index works fine, or why it's under 2 layers
        * (unused) ['otp'] - info about the service, such as account name, algorithm, period, etc.
        * ['secret'] - secret hash for the service
        * ['serviceTypeID'] - unknown
        * ['updatedAt'] - date in unix the service was updated
"""
import time

def switch_service_places(services: list, index1: int, index2: int):
    """Switches the places of two services in the list

    Args:
        services (list): List of services taken from secrets dict
        index1 (int): first target index
        index2 (int): second target index
    """

    temp = services[index1]

    services[index1] = services[index2]
    services[index2] = temp

    __update_order_position(services)

    return services

def drag_service_position(services:list, selected_index: int, pushed_index: int):
    """Drags a list to the selected index, and update the affected position values.

    e.g.

    ```
    abc 0               abc 0
    xyz 1 <- pushed     yup 1
    zip 2               xyz 2
    yup 3 <- selected   zip 3
    ```

    Args:
        services (list): List of services taken from secrets dict
        selected_index (int): Index of selected service to move
        pushed_index (int): Index to move the service to

    Raises:
        IndexError: Either the selected or pushed index is outside the range
    """
    if selected_index < 0 or selected_index > len(services):
        raise IndexError("selected_index outside range")

    if pushed_index < 0 or pushed_index > len(services):
        raise IndexError("pushed_index outside range")

    services[pushed_index] = services.pop(selected_index)
    __update_order_position(services)

def add_service(services: list, name: str, secret: str, index: int = None):
    """Adds a service to the list. If no index is selected, add it to the end

    Args:
        services (list): List of services taken from secrets dict
        name (str): name of service
        secret (str): OTP key
        index (int, optional): Index to insert service. If defaulted to None add to end
    """

    if index == None:
        index = len(services)

    service = {
        'group': "",
        'icon': {},
        'name': name,
        'order': {'position': index},
        'otp': {},
        'secret': secret,
        'serviceTypeID': '',
        'updatedAt': round(time.time() * 1000)
    }

    services.insert(index, service)

    __update_order_position(services)

def delete_service(services: list, index: int):
    """Selectes a service at a selected index

    Args:
        services (list): List of services from secrets dict
        index (int): Index of service to delete
    """

    list.pop(index)

    __update_order_position(services)

def __update_order_position(services: list):
    """Updates the list's ['order']['position'] values to match the actual index

    Not sure exactly why 2fas uses this instead of just the index but I'm keeping it.

    Args:
        services (list): List of services from secrets dict
    """
    for i, service in enumerate(services):
        service['order']['position'] = i

    return service

if __name__ == "__main__":
    from utils import locked_handler
    from cryptography.fernet import InvalidToken

    password = input("file password: ")
    try:
        services = locked_handler.decrypt_file_with_password(password)#['services']
    except InvalidToken:
        print("bad password")

    print()
