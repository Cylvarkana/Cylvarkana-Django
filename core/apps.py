"""
#!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        apps.py
Purpose:     Configuration for the Core Django application (Global Libraries)
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     9/30/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
import logging
from django.apps import AppConfig

# Configure logger for the Django application
logger = logging.getLogger("django")
app_name = 'core'

class CoreConfig(AppConfig):
    """
    Django application configuration for the Core app.
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = app_name
