"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        seed.py
Purpose:     Django CVE lookup
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
import os
from django.core.management import BaseCommand
from django.core.exceptions import ObjectDoesNotExist

from core.models import Credential
from biotremor.utils.system import seed_db

class Command(BaseCommand):
    """
    Register the runbot command to Django manage.py
    """
    help = 'Lookup a vulnerability'

    def add_arguments(self, parser):
        # Make the csv_file argument optional and provide a default value
        parser.add_argument(
            'csv_file',
            nargs='?',  # This makes the argument optional
            default=os.path.join('.', 'biotremor', 'data', 'seed.csv'),  # Default path
            type=str,
            help='Path to seed CSV file (default: ./biotremor/data/seed.csv)'
        )

        # Add the -f or --force argument
        parser.add_argument(
            '-f', '--force',
            action='store_true',
            help='Force pull updates'
        )

    def handle(self, *args, **options):
        csv_file = options['csv_file']
        force_updates = options['force']

        print(f"Seeding database with {csv_file}")

        try:
            # Pass pull_updates based on the presence of the force argument
            seed_db(
                csv_file,
                Credential.objects.get(platform='nist', cred_type='key').value,
                pull_updates=force_updates
            )
        except ObjectDoesNotExist:
            self.stderr.write("Lookup failed")
            return
