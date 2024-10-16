"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        lookup.py
Purpose:     Django CVE lookup
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from django.core.management import BaseCommand
from django.core.exceptions import ObjectDoesNotExist

from core.models import Credential
from biotremor.utils.system import cve_lookup

class Command(BaseCommand):
    """
    Register the runbot command to Django manage.py
    """
    help = 'Lookup a vulnerability'

    def add_arguments(self, parser):
        parser.add_argument('cve_id', type=str, help='CVE ID of the vulnerability')

    def handle(self, *args, **options):
        cve_id = options['cve_id']
        print(f"Looking up CVE: {cve_id}")

        # Retrieve the token from the Cred model
        try:
            cve_lookup(
                cve_id,
                nist_api_key = Credential.objects.get(cred_type="key", platform='nist').value,
                pull_updates=True
            )
        except ObjectDoesNotExist:
            self.stderr.write("Lookup failed")
            return

        print("\nRuntime!")
