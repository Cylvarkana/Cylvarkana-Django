"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        urls.py
Purpose:     Add url routes for ambivis app
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from django.urls import path
from .views import Tasking, ServerSync, summary
from .apps import app_name

urlpatterns = [
    path('', summary, name='summary'),
    path('api/v1/tasks', Tasking.as_view(), name='tasks'),
    path('api/v1/sync', ServerSync.as_view(), name='server-sync'),
]
