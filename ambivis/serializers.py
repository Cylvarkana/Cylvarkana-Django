"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        serializers.py
Purpose:     Serialize data for sending over API
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     9/12/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from rest_framework import serializers
from .models import *


class BotTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = BotTask
        fields = ['id', 'name', 'kwargs', 'created_at', 'processed']


class BotTaskUpdateSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    status = serializers.ChoiceField(choices=['complete', 'failed'])
