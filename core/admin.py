"""
#!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        admin.py
Purpose:     Register models for core use in the Django admin interface
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     9/30/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from django.contrib import admin
from django import forms
from .models import Credential

class CredForm(forms.ModelForm):
    """
    Custom form for the Credential model with enhanced input handling.
    """

    class Meta:
        """
        Model metadata configuration for the Credential form.
        """
        model = Credential
        fields = '__all__'
        widgets = {
            # Render value for password field
            'value': forms.PasswordInput(render_value=True)
        }

    class Media:
        """
        JavaScript and CSS files to be included in the form's media.
        """
         # Custom JS for toggling visibility of password input
        js = ('js/toggle_visibility.js',)


@admin.register(Credential)
class CredAdmin(admin.ModelAdmin):
    """
    Admin interface customization for the Credential model.
    """
    form = CredForm
    list_display = ('id', 'platform', 'cred_type', 'created_at')
