"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        urls.py
Purpose:     Add url routes for biotremor app
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from django.urls import path
from .views import Lookup, Rate
from .apps import app_name

urlpatterns = [
    path('api/v1/lookup', Lookup.as_view(), name='cve-lookup'),
    path('api/v1/rate', Rate.as_view(), name='rate-cve'),
]
