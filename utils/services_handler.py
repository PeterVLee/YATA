"""
Handles services + secrets dictionary by modifying groups and ordering

Follows 2fas' schema, which works like the following:

* `groups`: defines named folders for services to fall in to.
    * [i] - index of the group
        * ['id'] - unique id for group
        * ['name'] - user-defined name for group
        * (unused) ['isExpanded'] - says whether group is expanded
        * (unused) ['updatedAt'] - date in unix the group was updated

* `services`: defines the actual 2FA secrets.
    * [i] - index of the service
        * ['groupId'] - id of the group to shove this under
        * ['name'] - user-defined name for service
        * ['order']['position'] - also the index of the service
            * not sure why this is used here when the first index works fine, or why it's under 2 layers
        * ['secret'] - secret hash for the service
        * (unused) ['icon'] - info on icon to use for service
        * (unused) ['otp'] - info about the service, such as account name, algorithm, period, etc.
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

    services[index1]['order']['position'] = index1
    services[index2]['order']['position'] = index2

    return services

def drag_service_position(services:list, selected_index: int, pushed_index: int) -> list:
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

    Returns:
        list: Same list with dragged service
    """

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

if __name__ == "__main__":
    from utils import locked_handler
    password = input("file password: ")
    secrets = locked_handler.decrypt_file_with_password(password)
    services = secrets['services']
    switch_service_places(services, 0, 3)
    print()
