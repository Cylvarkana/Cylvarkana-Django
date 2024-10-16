"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        apps.py
Purpose:     Main configuration file for BioTremor Django App
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     9/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
import logging
from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.conf import settings

# App variables
logger = logging.getLogger("django")
app_name = 'biotremor'
group_name = 'BioTremor'


class BioTremorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = app_name

    def ready(self):
        """
        Connect the post_migrate signal to the system_configs function.
        """
        post_migrate.connect(system_configs, sender=self)


def system_configs(sender, **kwargs):
    """
    Define and set up the configurations required by the BioTremor app.

    Args:
        sender (AppConfig): The app configuration class that sent the signal.
        **kwargs: Additional keyword arguments from the signal.
    """
    from core.utils.system import system_checks
    from django_celery_beat.models import IntervalSchedule

    # Create required entities
    required_groups = [
        # Name, #Permissions
        group_name,
    ]
    required_users = [
        # username, password, groups
    ]
    required_creds = [
        # ID, Platform, Type, Value
        ('nist_service', 'nist', 'key', None)
    ]
    required_tasks = [
        # Task Name, Task Handle, Interval, Interval Units
    ]

    # Add Ambivis dependent configs
    if "ambivis" in settings.INSTALLED_APPS:
        required_users.append(("ambivis_service", None, [group_name]))

    # Create required configs
    system_checks(
        app_name,
        required_groups=required_groups,
        required_users=required_users,
        required_creds=required_creds,
        required_tasks=required_tasks
    )

    # Add default priorities
    create_priorities()


def create_priorities():
    """
    Create default priority entries in the database if they do not exist.

    This function checks for existing priority entries in the Priority model,
    and if none are found, it creates a set of default priorities with
    associated IDs and names.
    """
    from .models import Priority
    if not Priority.objects.exists():
        priorities = [
            (0, 'CRITICAL'),
            (1, 'HIGH'),
            (2, 'MEDIUM'),
            (3, 'LOW'),
            (4, 'UNKNOWN'),
        ]
        for id, name in priorities:
            Priority.objects.create(id=id, name=name)
