"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        checks.py
Purpose:     Run global app checks
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from django.db.utils import OperationalError
from django.contrib.auth.decorators import login_required
from core.apps import logger
from django.core.exceptions import PermissionDenied

def system_checks(
        app_name: str,
        required_groups: list = None,
        required_users: list = None,
        required_creds: list = None,
        required_tasks: list = None,
) -> None:
    """
    Run multiple startup tasks for default configurations after migration.
    
    Parameters:
        required_groups (list): A list of tuples, where each tuple contains:
            - name (str): The name of the group.
            
        required_users (list): A list of tuples, where each tuple contains:
            - username (str): The username of the user to create.
            - password (str): The password for the user (note: this will be ignored if the user already exists).
            - groups (list): A list of group names (str) to which the user should be assigned.
        
        required_creds (list): A list of tuples, where each tuple contains:
            - id (str): The unique ID of the credential.
            - platform (str): The platform associated with the credential.
            - cred_type (str): The type of the credential (e.g., 'token', 'password').
            - value (str): The value of the credential (can be None for placeholders).
        
        required_tasks (list): A list of tuples, where each tuple contains:
            - task_name (str): The display name of the task.
            - task (str): The task handle (the function that should be called).
            - every (int): The interval value for the task scheduling.
            - period (str): The interval period (e.g., IntervalSchedule.MINUTES, IntervalSchedule.HOURS).
    """
    from django.contrib.auth.models import User, Group, Permission
    from django_celery_beat.models import PeriodicTask, IntervalSchedule
    from core.models import Credential

    def create_placeholder_cred(
        id: str,
        platform: str,
        cred_type: str,
        value: str
    ):
        """
        Create a placeholder credential if not present.
        """
        try:
            _, created = Credential.objects.get_or_create(
                id=id,
                defaults={
                    "platform": platform,
                    "cred_type": cred_type,
                    "value": value
                })
            if created:
                logger.info(f'Added placeholder for system cred "{id}"')
        except OperationalError:
            logger.warning(f'Skipping creation of cred "{id}". Database not ready.')


    def create_user_group(name: str):
        """
        Create a user group and assign permissions for the app if not already present.
        """
        group, created = Group.objects.get_or_create(name=name)
        if created:
            logger.info(f'Group "{name}" created.')

        # Add permissions to the group
        app_permissions = Permission.objects.filter(content_type__app_label=app_name)
        group.permissions.set(app_permissions)
        logger.info(f'Permissions for "{app_name}" assigned to group "{group_name}".')

    def create_user(username: str, password: str, groups: list):
        """
        Create the user with a provided password if it doesn't exist, and assign groups.
        """
        try:
            if password:
                user, created = User.objects.get_or_create(
                    username=username,
                    defaults={'password': password}
                )
                if created:
                    logger.info(f"User '{username}' created with a secure random password.")
                else:
                    logger.info(f"User '{username}' already exists.")
            else:
                user = User.objects.get(username=username)

            # Fetch the groups to be added
            group_objs = Group.objects.filter(name__in=groups)

            # Add groups to the user rather than replacing them
            user.groups.add(*group_objs)
            logger.info(f'User "{username}" assigned to groups: {", ".join(groups)}.')

        except OperationalError:
            logger.warning(f"Skipping creation of user '{username}'. Database not ready.")
        except Exception as e:
            logger.error(f"Error creating user '{username}': {e}")

    def create_periodic_task(name: str, task: str, every: int, period):
        """
        Create or update a periodic task.
        """
        # Create or get the interval schedule
        interval, created = IntervalSchedule.objects.get_or_create(
            every=every,
            period=period
        )

        # Create or update the periodic task
        _, created = PeriodicTask.objects.get_or_create(
            interval=interval,
            name=name,
            defaults={
                'task': task,
                'one_off': False
            }
        )
        if created:
            logger.info(f'Created periodic task "{name}".')
        else:
            logger.info(f'Updated periodic task "{name}".')

    # Create groups first
    for group_name in required_groups:
        create_user_group(group_name)

    # Then create users
    for username, password, groups in required_users:
        create_user(username, password, groups)

    # Create credentials
    for cred_id, platform, cred_type, value in required_creds:
        create_placeholder_cred(cred_id, platform, cred_type, value)

    # Create periodic tasks
    for task_name, task, every, period in required_tasks:
        create_periodic_task(task_name, task, every, period)


def group_required(group_name):
    """
    Decorator to check if a user belongs to a specific group.
    """
    def decorator(view_func):
        @login_required  # Ensures the user is logged in
        def _wrapped_view(request, *args, **kwargs):
            if request.user.is_authenticated and request.user.groups.filter(name=group_name).exists():
                return view_func(request, *args, **kwargs)
            else:
                raise PermissionDenied("You do not have permission to access this page.")
        return _wrapped_view
    return decorator
