"""
#!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        models.py
Purpose:     Define core models used across the application
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     9/30/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""

from django.db import models
from encrypted_model_fields.fields import EncryptedCharField

class Credential(models.Model):
    """
    Model for managing user credentials.

    This model stores various types of credentials securely, including 
    the platform they are associated with and the type of credential.
    """

    # Options for supported platforms
    PLATFORM_CHOICES = [
        ('discord', 'Discord'),
        ('ambivis', 'Ambivis'),
        ('shodan', 'Shodan'),
        ('nist', 'NIST'),
    ]

    # Options for types of credentials
    CRED_TYPES = [
        ('password', 'Password'),
        ('secret', 'Secret'),
        ('token', 'Token'),
        ('key', 'Key'),
    ]

    id = models.CharField(max_length=50, primary_key=True)
    platform = models.CharField(max_length=50, choices=PLATFORM_CHOICES)
    cred_type = models.CharField(max_length=50, choices=CRED_TYPES)
    value = EncryptedCharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """
        Returns the unique identifier of the credential.
        """
        return self.id
