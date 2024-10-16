"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        apps.py
Purpose:     Main configuration file for Ambivis Django App
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
import logging
from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.utils.crypto import get_random_string

# App variables
logger = logging.getLogger("django")
app_name = "ambivis"
group_name = "BotMaster"


class AmbivisConfig(AppConfig):
    """
    Main configuration class for the Ambivis Django app
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = app_name

    def ready(self):
        """
        Execute tasks on app startup
        """
        post_migrate.connect(system_configs, sender=self)


def system_configs(sender, **kwargs):
    """
    Define configs required by the app
    """
    from core.utils.system import system_checks
    from django_celery_beat.models import IntervalSchedule

    # Generate a random secure password for the user
    password = get_random_string(length=20)

    # Create required entities
    required_groups = [
        # Name, #Permissions
        group_name,
    ]
    required_users = [
        # username, password, groups
        ('ambivis_service', password, [group_name]),
    ]
    required_creds = [
        # ID, Platform, Type, Value
        ('ambivis_discord', 'discord', 'token', None),
        ('ambivis_service', 'ambivis', 'password', password),
        ('shodan_service', 'shodan', 'key', None)
    ]
    required_tasks = [
        # Task Name, Task Handle, Interval, Interval Units
        ('Fetch RSS', 'Fetch RSS', 10, IntervalSchedule.MINUTES),
        ('Sync Discord Configs', 'Sync Discord Configs', 1, IntervalSchedule.HOURS),
        ('Clear Bot Task Logs', 'Clear Bot Task Logs', 1, IntervalSchedule.DAYS)
    ]

    # Create required configs
    system_checks(
        app_name,
        required_groups=required_groups,
        required_users=required_users,
        required_creds=required_creds,
        required_tasks=required_tasks
    )
