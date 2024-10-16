"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        serializers.py
Purpose:     Define serializers for the Biotremor app to convert model instances
             to JSON and validate incoming data.
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     9/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""

from rest_framework import serializers
from .models import CVE, CVERating

class CVESerializer(serializers.ModelSerializer):
    """
    This serializer handles the conversion of CVE model instances
    """

    class Meta:
        "Customize model and fields returned"
        model = CVE
        fields = '__all__'


class CVERatingSerializer(serializers.ModelSerializer):
    """
    This serializer manages the conversion of CVERating model
    """

    class Meta:
        "Customize model and fields returned"
        model = CVERating
        fields = ['cve', 'priority', 'method', 'source', 'created_at', 'updated']
