"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        api.py
Purpose:     Provide utility functions and classes for API interactions
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     9/30/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
import time
import requests
from core.apps import app_name
from django.conf import settings


def retry_request(
        url: str,
        method: str,
        headers: dict = None,
        max_retries: int = 3,
        params=None,
        json=None,
        backoff_time: int = 3
    ):
    """
    Retry a request for unreliable APIs.

    Args:
        url (str): The API endpoint URL.
        method (str): The HTTP method ('get' or 'post').
        headers (dict, optional): HTTP headers for the request.
        max_retries (int): Maximum number of retry attempts.
        params (dict, optional): Query parameters for the request.
        json (dict, optional): JSON data to send with the request.
        backoff_time (int): Delay in seconds between retries.

    Returns:
        Response or dict: API response on success, empty dict on failure.
    """
    for attempt in range(max_retries):
        try:
            if method == 'get':
                response = requests.get(url, headers=headers, params=params, json=json)
            elif method == 'post':
                response = requests.post(url, headers=headers, params=params, json=json)
            return response
        except Exception as e:
            print(e, f"Attempt {attempt + 1} of {max_retries}")
            time.sleep(backoff_time)

    print(f"ERROR: Failed to {method} {url}")
    return {}


class CoreAPI:
    """
    Core API client for JWT authentication and token management.
    """

    def __init__(self, username: str, password: str, api_base_url: str) -> None:
        self.api_base_url = api_base_url
        self.username = username
        self.password = password
        self.token = None
        self.refresh_token = None
        self.authenticate()

    def authenticate(self) -> None:
        """
        Authenticate user and fetch JWT tokens.
        """
        url = f"http://{settings.HOSTNAME}/{app_name}/api/v1/auth"
        headers = {"Content-Type": "application/json"}
        data = {"username": self.username, "password": self.password}

        response = requests.post(url, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            token_data = response.json()
            self.token = token_data.get('access')
            self.refresh_token = token_data.get('refresh')
        else:
            raise Exception(f"Authentication failed: {response.status_code} - {response.text}")

    def refresh_auth_token(self) -> None:
        """
        Refresh the JWT access token using the refresh token.
        """
        url = f"http://{settings.HOSTNAME}/{app_name}/api/v1/refresh"
        headers = {"Content-Type": "application/json"}
        data = {"refresh": self.refresh_token}

        response = requests.post(url, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            self.token = response.json().get('access')
        else:
            raise Exception(f"Token refresh failed: {response.status_code} - {response.text}")

    def get_headers(self) -> dict:
        """
        Generate headers for API requests including the authorization token.

        Returns:
            dict: Headers with authorization token.
        """
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
