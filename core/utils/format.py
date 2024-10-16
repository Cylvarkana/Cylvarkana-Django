"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        format.py
Purpose:     Custom formatter functions and classes for logging and validation
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""

import re
import logging
from colorama import init, Fore, Style

# Initialize colorama for colored logging
init(autoreset=True)

class ColorFormatter(logging.Formatter):
    """
    Custom logging formatter that adds color to log messages based on their level.
    """
    COLORS = {
        'DEBUG': Fore.CYAN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }

    def __init__(self, fmt=None, datefmt=None, style='{', _stdout=False):
        super().__init__(fmt, datefmt, style)

        # Determines if output should be colored
        self._stdout = _stdout

    def format(self, record):
        """
        Format the log record and add color if _stdout is True.
        
        Args:
            record: The log record to format.

        Returns:
            str: The formatted log message with appropriate color.
        """
        formatted_message = super().format(record)

        if self._stdout:
            log_color = self.COLORS.get(record.levelname, '')
            formatted_message = f"{log_color}{formatted_message}{Style.RESET_ALL}"

        return formatted_message

def validate_cve(cve_id: str) -> str:
    """
    Validate and normalize a CVE ID.

    Args:
        cve_id (str): The CVE ID to validate.

    Returns:
        str: Normalized CVE ID in uppercase if valid; None otherwise.
    """
    # Regex pattern for CVE validation
    cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE)

    if cve_pattern.match(cve_id):

        # Normalize to uppercase
        return cve_id.upper()

    # Return None if invalid
    return None

def validate_ip(ip_address: str) -> str:
    """
    Validate the format of an IPv4 address.

    Args:
        ip_address (str): The IPv4 address to validate.

    Returns:
        str: Valid IPv4 address if valid; None otherwise.
    """
    # Regex pattern for IPv4 validation
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

    if ipv4_pattern.match(ip_address):
        octets = ip_address.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):

            # Return valid address
            return ip_address

    # Return None if invalid
    return None

def validate_domain(domain: str) -> str:
    """
    Validate and normalize a domain name.

    Args:
        domain (str): The domain name to validate.

    Returns:
        str: Normalized domain name in lowercase if valid; None otherwise.
    """
    # Regex pattern for domain validation
    domain_pattern = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)\.[a-z]{2,6}$')

    if domain_pattern.match(domain.lower()):

        # Normalize to lowercase
        return domain.lower()

    # Return None if invalid
    return None
