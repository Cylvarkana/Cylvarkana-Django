"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        api.py
Purpose:     Custom API wrappers for supporting django apps
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
import requests
from bs4 import BeautifulSoup
from django.conf import settings
from ambivis.apps import app_name
from core.utils.api import CoreAPI

def fetch_opengraph_data(url: str) -> dict:
    """
    Fetch OpenGraph metadata from a given URL using BeautifulSoup.
    
    :param url: The URL to scrape for OpenGraph metadata.
    :return: A dictionary of OpenGraph metadata, or None if not available.
    """
    # Define headers to mimic a user
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "DNT": "1",  # Do Not Track request header
        "Upgrade-Insecure-Requests": "1",
        "Referer": "https://www.google.com/"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")
        og_data = {}

        for og_tag in soup.find_all("meta"):
            if og_tag.get("property", "").startswith("og:"):
                og_data[og_tag["property"][3:]] = og_tag["content"]

        return og_data if og_data else None
    except requests.RequestException as e:
        print(f"Error fetching OpenGraph data: {e}")
        return None

class Ambivis(CoreAPI):
    """
    Wrapper for Ambivis API with JWT authentication
    """
    
    def __init__(self, username: str, password: str) -> None:
        api_base_url = f"http://{settings.HOSTNAME}/{app_name}"
        super().__init__(username, password, api_base_url)

    def get_tasks(self) -> dict:
        """
        Fetch unprocessed bot tasks from the API
        """
        url = f"{self.api_base_url}/api/v1/tasks"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json"
        }

        response = requests.get(url, headers=headers, timeout=10)

        # Check if token has expired
        if response.status_code == 401:
            self.refresh_auth_token()
            # Retry the request with the refreshed token
            headers["Authorization"] = f"Bearer {self.token}"
            response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to fetch unprocessed tasks: {response.status_code} - {response.text}")

    def post_task_status(self, task_id: int, status: str) -> dict:
        """
        Update the status of a task
        """
        url = f"{self.api_base_url}/api/v1/tasks"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        data = {
            "id": task_id,
            "status": status
        }
        response = requests.post(url, headers=headers, json=data, timeout=10)

        if response.status_code == 401:
            self.refresh_auth_token()
            headers["Authorization"] = f"Bearer {self.token}"
            response = requests.post(url, headers=headers, json=data, timeout=10)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to update task status: {response.status_code} - {response.text}")
    
    def sync_server_data(self, data: dict) -> requests.Response:
        """
        Sync server data (channels, users, roles, ect.) to the Ambivis API.
        """
        url = f"{self.api_base_url}/api/v1/sync"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        response = requests.post(url, headers=headers, json=data)

        if response.status_code == 401:
            self.refresh_auth_token()
            headers["Authorization"] = f"Bearer {self.token}"
            response = requests.post(url, headers=headers, json=data, timeout=10)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to sync server: {response.status_code} - {response.text}")
