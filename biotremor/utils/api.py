"""
!/usr/bin/env python3
 -*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:       api
Purpose:    Manage all external API interfaces
Author:     Kodama Chameleon <contact@kodamachameleon.com>
Created:    08/13/2024
-------------------------------------------------------------------------------
"""
import requests
from requests.exceptions import HTTPError
from ratelimit import limits, sleep_and_retry
from django.conf import settings
from biotremor.apps import app_name
from core.utils.api import CoreAPI, retry_request

def validate_kwargs(kwargs: dict, authorized_kwargs: dict):
    """
    Validate key and value type of kwargs
    """
    for key, value in kwargs.items():
        if key in authorized_kwargs:
            expected_type = authorized_kwargs[key]
            if not isinstance(value, expected_type):
                raise TypeError(f"Parameter '{key}' should be of type {expected_type.__name__}, but got {type(value).__name__}.")
        else:
            raise ValueError(f"Parameter '{key}' is not a valid parameter.")


class Mitre:
    """
    Python wrapper for the MITRE CWE API.
    https://cwe.mitre.org/
    """

    def __init__(self) -> None:
        """
        Initialize API handle
        """
        self.base_url = "https://cwe-api.mitre.org/api/v1/cwe"
        self.headers = {
            'Content-Type': 'application/json'
        }

    @sleep_and_retry
    @limits(calls=30, period=60)
    def fetch_weakness_details(self, cwe_id: int) -> dict:
        """
        Fetch CWE details from MITRE API for a given CWE ID.

        Parameters:
        -----------
        cwe_id : str
            The CWE ID to fetch details for (e.g., "306").

        Returns:
        --------
        dict
            Returns the JSON response containing CWE details from MITRE API.
        """
        # Construct the URL for fetching CWE details
        api_endpoint = f"{self.base_url}/weakness/{cwe_id}"
        try:
            response = requests.get(api_endpoint, timeout=60)
            response.raise_for_status()
            return response.json()
        except HTTPError as e:
            # Handle specific 404 error to check if we should switch to category endpoint
            if e.response.status_code == 404:
                response_content = e.response.content.decode('utf-8')
                if "use the category endpoint" in response_content:
                    return self.fetch_category_details(cwe_id)
                if "use the view endpoint" in response_content:
                    return self.fetch_view_details(cwe_id)
                else:
                    raise e
            else:
                raise e

    @sleep_and_retry
    @limits(calls=30, period=60)
    def fetch_category_details(self, cwe_id: int) -> dict:
        """
        Fetch details for a specific CWE category ID.

        Parameters:
        -----------
        cwe_id : int
            The CWE category ID to fetch details for.

        Returns:
        --------
        dict
            Returns the JSON response from the CWE category API if successful.
        """
        # Set the URL for the CWE category API
        api_endpoint = f"{self.base_url}/category/{cwe_id}"

        response = requests.get(api_endpoint, timeout=60)
        response.raise_for_status()
        return response.json()

    @sleep_and_retry
    @limits(calls=30, period=60)
    def fetch_view_details(self, cwe_id: int) -> dict:
        """
        Fetch details for a specific CWE view ID.

        Parameters:
        -----------
        cwe_id : int
            The CWE view ID to fetch details for.

        Returns:
        --------
        dict
            Returns the JSON response from the CWE view API if successful.
        """
        # Set the URL for the CWE view API
        api_endpoint = f"{self.base_url}/view/{cwe_id}"

        response = requests.get(api_endpoint, timeout=60)
        response.raise_for_status()
        return response.json()


class First:
    """
    Python wrapper for First API
    https://www.first.org/
    """

    def __init__(self) -> None:
        """
        Initialize API handle
        """
        self.base_url = "https://api.first.org/data/v1"
        self.headers = {
            'Content-Type': 'application/json'
        }

    @sleep_and_retry
    @limits(calls=30, period=60)
    def fetch_epss_score(self, **kwargs) -> dict:
        """
        Retrieves EPSS scores from the FIRST API based on provided parameters.

        Parameters:
        -----------
        max_retries : int, optional
            The number of times to retry the API request in case of failure (default is 3).
        kwargs : dict
            Additional parameters to filter the EPSS results.

        Returns:
        --------
        dict or None
            Returns the JSON response from the FIRST API if successful, otherwise returns None.
        """
        # Define authorized parameters and their expected types
        authorized_parameters = {
            "cve": str,  # Filter by CVE ID(s), supports multiple values separated by commas.
            "date": str,  # Filter by specific date in the format YYYY-MM-DD.
            "days": int,  # Filter by number of days since the EPSS score was added.
            "epss-gt": float,  # Filter by EPSS score greater than or equal to this value.
            "percentile-gt": float,  # Filter by percentile greater than or equal to this value.
            "epss-lt": float,  # Filter by EPSS score less than or equal to this value.
            "percentile-lt": float,  # Filter by percentile less than or equal to this value.
            "q": str,  # Free text search for partial matches at the CVE ID.
            "scope": str,  # Filter by scope (e.g., "public" or "time-series").
        }
        validate_kwargs(kwargs, authorized_parameters)

        # Set the URL for the EPSS API
        api_endpoint = f"{self.base_url}/epss"

        # Construct parameters
        params = kwargs

        # Use the retry_request function to handle the API request with retries
        response = retry_request(
            api_endpoint,
            'get',
            headers=self.headers,
            params=params
        )
        response.raise_for_status()

        return response.json()

    @sleep_and_retry
    @limits(calls=30, period=60)
    def fetch_countries(self, **kwargs) -> dict:
        """
        Retrieves country and region data from the FIRST API based on provided parameters.

        Parameters:
        -----------
        max_retries : int, optional
            The number of times to retry the API request in case of failure (default is 3).
        kwargs : dict
            Additional parameters to filter the country results.

        Returns:
        --------
        dict or None
            Returns the JSON response from the FIRST API if successful, otherwise returns None.
        """

        # Define authorized parameters and their expected types
        authorized_parameters = {
            "region": str,  # Filter by region of the country.
            "q": str,  # Free text search for country name, abbreviations, and region.
        }
        validate_kwargs(kwargs, authorized_parameters)

        # Set the URL for the Countries API
        api_endpoint = f"{self.base_url}/countries"

        # Construct parameters
        params = kwargs

        # Use the retry_request function to handle the API request with retries
        response = retry_request(
            api_endpoint,
            'get',
            headers=self.headers,
            params=params
        )
        response.raise_for_status()

        return response.json()

    @sleep_and_retry
    @limits(calls=30, period=60)
    def fetch_news(self, **kwargs) -> dict:
        """
        Retrieves news items from the FIRST API based on provided parameters.

        Parameters:
        -----------
        max_retries : int, optional
            The number of times to retry the API request in case of failure (default is 3).
        kwargs : dict
            Additional parameters to filter the news results.

        Returns:
        --------
        dict or None
            Returns the JSON response from the FIRST API if successful, otherwise returns None.
        """

        # Define authorized parameters and their expected types
        authorized_parameters = {
            "channel": str,  # Filter by news channel title.
            "link": str,  # Filter by news item URL.
            "before": str,  # ISO 8601 formatted date to return news older than this date.
            "after": str,  # ISO 8601 formatted date to return news newer than this date.
            "q": str,  # Free text search for news title, summary, and URL.
        }
        validate_kwargs(kwargs, authorized_parameters)

        # Set the URL for the News API
        api_endpoint = f"{self.base_url}/news"

        # Construct parameters
        params = kwargs

        # Use the retry_request function to handle the API request with retries
        response = retry_request(
            api_endpoint,
            'get',
            headers=self.headers,
            params=params
        )
        response.raise_for_status()

        return response.json()

    @sleep_and_retry
    @limits(calls=30, period=60)
    def fetch_teams(self, **kwargs) -> dict:
        """
        Retrieves team information from the FIRST API based on provided parameters.

        Parameters:
        -----------
        max_retries : int, optional
            The number of times to retry the API request in case of failure (default is 3).
        kwargs : dict
            Additional parameters to filter the team results.

        Returns:
        --------
        dict or None
            Returns the JSON response from the FIRST API if successful, otherwise returns None.
        """

        # Define authorized parameters and their expected types
        authorized_parameters = {
            "country": str,  # Filter by ISO 2-letter country code.
            "region": str,  # Filter by continental region.
            "team": str,  # Filter by short team name.
            "q": str,  # Free text search for team name, country, and country name.
        }
        validate_kwargs(kwargs, authorized_parameters)

        # Set the URL for the Teams API
        api_endpoint = f"{self.base_url}/teams"

        # Construct parameters
        params = kwargs

        # Use the retry_request function to handle the API request with retries
        response = retry_request(
            api_endpoint,
            'get',
            headers=self.headers,
            params=params
        )
        response.raise_for_status()

        return response.json()


class NIST:
    """
    Python wrapper for NVD NIST API
    https://nvd.nist.gov/
    """

    def __init__(self, api_key) -> None:
        """
        Initialize API handle
        """
        self.api_key = api_key
        self.headers = {
            'apiKey': self.api_key,
            'Content-Type': 'application/json'
        }
        self.base_url = "https://services.nvd.nist.gov/rest/json"

        # Add backoff time for slow NIST API
        self.backoff_time = 5

    @sleep_and_retry
    @limits(calls=30, period=60)
    def fetch_cve_data(self, **kwargs) -> dict:
        """
        Retrieves CVE information from the NVD API based on provided parameters.
        
        Parameters:
        -----------
        max_retries : int, optional
            The number of times to retry the API request in case of failure (default is 3).
        kwargs : dict
            Additional parameters to filter the CVE results.
        
        Returns:
        --------
        dict or None
            Returns the JSON response from the NVD API if successful, otherwise returns None.
        """

        # Check that each kwarg has the correct type
        authorized_parameters = {
            "cveId": str,  # Filter by a specific CVE ID (e.g., "CVE-2021-44228").
            "cpeName": str,  # Filter by CPE Name (e.g., "cpe:2.3:a:example:software:1.0:*:*:*:*:*:*:*").
            "cpeMatchString": str,  # Filter by CPE match string.
            "cveStatus": str,  # Filter by CVE status (e.g., "Analyzed", "Modified").
            "cvssV2Severity": str,  # Filter by CVSS v2 severity (e.g., "LOW", "MEDIUM", "HIGH").
            "cvssV3Severity": str,  # Filter by CVSS v3 severity (e.g., "LOW", "MEDIUM", "HIGH", "CRITICAL").
            "hasCertAlerts": bool,  # Filter by whether the CVE has CERT alerts (true or false).
            "hasCertNotes": bool,  # Filter by whether the CVE has CERT notes (true or false).
            "hasKev": bool,  # Filter by whether the CVE is included in Known Exploited Vulnerabilities (KEV).
            "hasOval": bool,  # Filter by whether the CVE has Open Vulnerability Assessment Language (OVAL) definitions.
            "isVulnerable": bool,  # Filter by whether the CVE is vulnerable.
            "keywordSearch": str,  # Filter by keywords.
            "lastModStartDate": str,  # Filter by the last modification start date (ISO 8601 format).
            "lastModEndDate": str,  # Filter by the last modification end date (ISO 8601 format).
            "pubStartDate": str,  # Filter by the publication start date (ISO 8601 format).
            "pubEndDate": str,  # Filter by the publication end date (ISO 8601 format).
            "sourceIdentifier": str,  # Filter by the source identifier.
            "virtualMatchString": str,  # Filter by a virtual match string.
            "versionStart": str,  # Filter by the start version for version range filtering.
            "versionEnd": str,  # Filter by the end version for version range filtering.
            "resultsPerPage": int,  # Number of results to return per page (default is 20).
            "startIndex": int,  # The index of the first result to return (default is 0).
            "includeMatchStringChange": bool,  # Whether to include match string changes in the results.
            "noRejected": bool  # Whether to exclude rejected CVEs (default is false).
        }
        validate_kwargs(kwargs, authorized_parameters)

        # Set the URL
        url = f"{self.base_url}/cves/2.0"

        # Construct parameters
        params = {
            'resultsPerPage': kwargs.get('resultsPerPage', 20),
            'startIndex': kwargs.get('startIndex', 0)
        }
        params.update(kwargs)

        # Use the retry_request function to handle the API request with retries
        response = retry_request(
            url,
            'get',
            headers=self.headers,
            backoff_time=self.backoff_time,
            params=params
        )
        response.raise_for_status()

        return response.json()

    @sleep_and_retry
    @limits(calls=30, period=60)
    def fetch_cve_history(self, **kwargs) -> dict:
        """
        Retrieves CVE change history information from the NVD API based on provided parameters.

        Parameters:
        -----------
        max_retries : int, optional
            The number of times to retry the API request in case of failure (default is 3).
        kwargs : dict
            Additional parameters to filter the CVE change history results.

        Returns:
        --------
        dict or None
            Returns the JSON response from the NVD API if successful, otherwise returns None.
        """

        # Define authorized parameters and their expected types
        authorized_parameters = {
            "changeStartDate": str,  # Start date for the change history (ISO 8601 format).
            "changeEndDate": str,  # End date for the change history (ISO 8601 format).
            "cveId": str,  # Specific CVE ID to fetch change history for.
            "eventName": str,  # Specific event name to filter by.
            "resultsPerPage": int,  # Number of results to return per page (default is 5000).
            "startIndex": int,  # The index of the first result to return (default is 0).
        }
        validate_kwargs(kwargs, authorized_parameters)

        # Validate required date parameters when both changeStartDate and changeEndDate are provided
        if "changeStartDate" in kwargs or "changeEndDate" in kwargs:
            if not ("changeStartDate" in kwargs and "changeEndDate" in kwargs):
                raise ValueError("Both 'changeStartDate' and 'changeEndDate' must be provided together.")

        # Set the URL for the CVE Change History API
        url = f"{self.base_url}/cvehistory/2.0"

        # Construct parameters
        params = {
            'resultsPerPage': kwargs.get('resultsPerPage', 5000),
            'startIndex': kwargs.get('startIndex', 0)
        }
        params.update(kwargs)

        # Use the retry_request function to handle the API request with retries
        response = retry_request(
            url,
            'get',
            self.headers,
            backoff_time=self.backoff_time,
            params=params
        )
        response.raise_for_status()

        return response.json()


class BioTremor(CoreAPI):
    """
    Wrapper for BioTremor API with JWT authentication
    """

    def __init__(self, username: str,password: str,) -> None:
        """
        Initialize an API handle
        """
        api_base_url = f"http://{settings.HOSTNAME}/{app_name}"
        super().__init__(username, password, api_base_url)


    def lookup(self, cve_id: str) -> dict:
        """
        Fetch CVE data for a given CVE ID from BioTremor API
        """
        url = f"{self.api_base_url}/api/v1/lookup"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json"
        }
        data = {"cve_id": cve_id}

        response = requests.post(url, headers=headers, json=data, timeout=60)

        if response.status_code == 401:
            self.refresh_auth_token()
            headers["Authorization"] = f"Bearer {self.token}"
            response = requests.post(url, headers=headers, json=data, timeout=60)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to lookup CVE: {response.status_code} - {response.text}")


    def rate(self, cve_id: str, priority: str, source: str) -> dict:
        """
        Create or update priority rating for a given CVE ID on BioTremor API
        """
        url = f"{self.api_base_url}/api/v1/rate"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        data = {
            "cve_id": cve_id,
            "priority": priority,
            "source": source
        }

        response = requests.post(url, headers=headers, json=data, timeout=10)

        if response.status_code == 401:
            self.refresh_auth_token()
            headers["Authorization"] = f"Bearer {self.token}"
            response = requests.post(url, headers=headers, json=data, timeout=10)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to rate CVE: {response.status_code} - {response.text}")
