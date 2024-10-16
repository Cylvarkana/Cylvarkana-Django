"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        urls.py
Purpose:     Add url routes for core app
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .apps import app_name

urlpatterns = [
    path('api/v1/auth', TokenObtainPairView.as_view(), name='obtain_token'),
    path('api/v1/refresh', TokenRefreshView.as_view(), name='refresh_token'),
]
