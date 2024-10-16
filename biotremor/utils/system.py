"""
!/usr/bin/env python3
 -*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:       system
Purpose:    Primary data processing for the application
Author:     Kodama Chameleon <contact@kodamachameleon.com>
Created:    08/14/2024
-------------------------------------------------------------------------------
"""
import os
from datetime import datetime
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist

from core.utils.format import validate_cve
from biotremor.apps import logger
from biotremor.models import (
    CVE,
    Priority,
    CVERating,
    CWE,
    EPSS,
    Description,
    CVSSMetricV20,
    CVSSMetricV31,
    Weakness,
    Configuration,
    Reference,
    CVEChange,
    ChangeDetail
)

from .api import NIST, First, Mitre

def seed_db(csv_file_path: str, nist_api_key: str, pull_updates: bool = False):
    """
    Seed the database with data from a csv file
    args:
        csv_file_path (str): Path to the CSV file containing CVE IDs and Priorities.
        nist_api_key (str): NIST API key for fetching CVE data.
        pull_updates (bool): Flag to indicate whether to pull updates if CVE already exists.
    """
    if not os.path.exists(csv_file_path):
        raise ValueError(f"File path not found: {csv_file_path}")

    Priorities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    for line in open(csv_file_path, encoding="utf-8"):

        try:
            # Parse cve_id and priority from the line
            cve_id, priority_name = line.split(',')

            # Normalize the values
            cve_id = validate_cve(cve_id.strip())
            priority_name = priority_name.strip().upper()

            # Input validation
            if not cve_id:
                raise ValueError(f"Invalid CVE ID format")

            if priority_name not in Priorities:
                raise ValueError(f"Invalid priority: {priority_name}")

        except ValueError:
            logger.error(f"Invalid line format: {line}")
            continue

        logger.info(f"Looking up CVE: {cve_id}...")

        try:
            # Check if CVE already in the database
            cve = CVE.objects.filter(id=cve_id).first()

            # Pull data if not found or if updates are requested
            if not cve or pull_updates:
                logger.info(f"Updating local data for {cve_id}...")
                cve = cve_lookup(cve_id, nist_api_key=nist_api_key, pull_updates=True)

            if cve:
                priority = Priority.objects.get(name=priority_name)
                if priority:
                    rating, created = CVERating.objects.update_or_create(
                        cve=cve,
                        defaults={
                            'priority': priority,
                            'method': 'manual',
                            'source': csv_file_path,
                        }
                    )
                    if created:
                        logger.info(f"Rated {cve.id} as {rating.priority} via {csv_file_path}")

        except ObjectDoesNotExist:
            logger.error("Lookup failed")
            return


def cve_lookup(cveId: str, nist_api_key: str=None, pull_updates: bool = False) -> CVE:
    """
    Lookup data for a given CVE ID
    """

    cve = CVE.objects.filter(id=cveId).first()

    # Verify NIST API key if pulling updates
    if pull_updates and not nist_api_key:
        raise ValueError("NIST API key is required to pull updates.")

    # Pull updates from API vendors
    if (pull_updates and nist_api_key) or not cve:

        # Create necessary object handles
        nist_handle = NIST(nist_api_key)
        first_handle = First()

        # Import NIST data
        cve_data = nist_handle.fetch_cve_data(cveId=cveId)
        convert_nist_cve(cve_data)

        cve_history = nist_handle.fetch_cve_history(cveId=cveId)
        convert_nist_history(cve_history)

        # Import FIRST data
        first_data = first_handle.fetch_epss_score(cve=cveId)
        convert_FIRST_epss(first_data)

        cve = CVE.objects.filter(id=cveId).first()

    return cve


def cwe_lookup(cwe_id: int, pull_updates: bool = False) -> CWE:
    """
    Lookup data for a given CWE ID.

    Parameters:
    -----------
    cwe_id : int
        The CWE ID to look up.
    pull_updates : bool, optional
        If True, will pull updates from the MITRE API, even if the CWE exists locally.
    """

    # Attempt to find the CWE instance locally
    cwe = CWE.objects.filter(id=cwe_id).first()

    # If not found locally or if pull_updates is requested
    if not cwe or pull_updates:

        # Create an instance of the Mitre API wrapper
        mitre_handle = Mitre()

        # Fetch CWE data from the MITRE API
        cwe_data = mitre_handle.fetch_weakness_details(cwe_id=cwe_id)
        convert_mitre_cwe(cwe_data)

        # Fetch the CWE from the database after updating/inserting
        cwe = CWE.objects.filter(id=cwe_id).first()

    return cwe


def convert_FIRST_epss(first_data: dict):
    """
    Convert FIRST EPS data to the database model
    """
    for vuln in first_data['data']:
        cve = CVE.objects.get(id=vuln['cve'])
        if cve:
            epss, created = EPSS.objects.update_or_create(
                cve=cve,
                defaults={
                    'score': vuln.get('epss', None),
                    'percentile': vuln.get('percentile', None),
                    'date': vuln.get('date', None),
                }
            )
            if created:
                logger.info(f"Created EPSS entry ({epss.score}) for {cve.id}")

def convert_nist_cve(cve_data: dict):
    """
    Import NIST results to local database
    """
    # Iterate over all vulnerabilities returned
    for vuln in cve_data.get('vulnerabilities', []):
        cve_info = vuln.get('cve', {})

        # Parse the datetime strings and convert to timezone-aware datetimes
        published = datetime.strptime(cve_info['published'], '%Y-%m-%dT%H:%M:%S.%f')
        if timezone.is_naive(published):
            published = timezone.make_aware(published, timezone.get_current_timezone())

        last_modified = datetime.strptime(cve_info['lastModified'], '%Y-%m-%dT%H:%M:%S.%f')
        if timezone.is_naive(last_modified):
            last_modified = timezone.make_aware(last_modified, timezone.get_current_timezone())

        cve, created = CVE.objects.update_or_create(
            id=cve_info['id'],
            defaults={
                'source_identifier': cve_info['sourceIdentifier'],
                'published': published,
                'last_modified': last_modified,
                'vuln_status': cve_info['vulnStatus'],
                'cisa_exploit_add': cve_info.get('cisaExploitAdd'),
                'cisa_action_due': cve_info.get('cisaActionDue'),
                'cisa_required_action': cve_info.get('cisaRequiredAction'),
                'cisa_vulnerability_name': cve_info.get('cisaVulnerabilityName'),
            }
        )
        if created:
            logger.info(f"Created CVE entry for {cve.id}")

        if cve:
            for desc in cve_info.get('descriptions', []):
                _, created = Description.objects.update_or_create(
                    cve=cve,
                    lang=desc['lang'],
                    defaults={'value': desc['value']}
                )
                if created:
                    logger.info(f"Added description for {cve.id}")

            for metric in cve_info.get('metrics', {}).get('cvssMetricV31', []):
                cvss_data = metric['cvssData']
                cvss_metric, created = CVSSMetricV31.objects.update_or_create(
                    cve=cve,
                    defaults={
                        'source': metric['source'],
                        'type': metric['type'],
                        'vector_string': cvss_data['vectorString'],
                        'attack_vector': cvss_data['attackVector'],
                        'attack_complexity': cvss_data['attackComplexity'],
                        'privileges_required': cvss_data['privilegesRequired'],
                        'user_interaction': cvss_data['userInteraction'],
                        'scope': cvss_data['scope'],
                        'confidentiality_impact': cvss_data['confidentialityImpact'],
                        'integrity_impact': cvss_data['integrityImpact'],
                        'availability_impact': cvss_data['availabilityImpact'],
                        'base_score': cvss_data['baseScore'],
                        'base_severity': cvss_data['baseSeverity'],
                        'exploitability_score': metric['exploitabilityScore'],
                        'impact_score': metric['impactScore'],
                    }
                )
                if created:
                    logger.info(f"Added CVSS vector {cvss_metric.vector_string} for {cve.id}")

            # Handle CVSS 2.0 Metrics
            for metric in cve_info.get('metrics', {}).get('cvssMetricV2', []):
                cvss_data = metric['cvssData']
                cvss_metric, created = CVSSMetricV20.objects.update_or_create(
                    cve=cve,
                    defaults={
                        'source': metric['source'],
                        'type': metric['type'],
                        'vector_string': cvss_data['vectorString'],
                        'access_vector': cvss_data['accessVector'],
                        'access_complexity': cvss_data['accessComplexity'],
                        'authentication': cvss_data['authentication'],
                        'confidentiality_impact': cvss_data['confidentialityImpact'],
                        'integrity_impact': cvss_data['integrityImpact'],
                        'availability_impact': cvss_data['availabilityImpact'],
                        'base_score': cvss_data['baseScore'],
                        'severity': metric['baseSeverity'],
                        'exploitability_score': metric['exploitabilityScore'],
                        'impact_score': metric['impactScore'],
                    }
                )
                if created:
                    logger.info(f"Added CVSS 2.0 vector {cvss_metric.vector_string} for {cve.id}")

            # Weakness handling with CWE foreign key lookup
            for weakness in cve_info.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    # Extract CWE ID
                    cwe_id = None
                    if isinstance(desc['value'], str) and desc['value'].startswith('CWE-'):
                        try:
                            cwe_id = int(desc['value'].split('-')[1])
                        except (IndexError, ValueError):
                            logger.warning(f"Invalid CWE format for description: {desc['value']}")

                    # Lookup CWE
                    cwe_instance = None
                    if cwe_id:
                        try:
                            cwe_instance = cwe_lookup(cwe_id)
                        except Exception as e:
                            logger.error(f"Error looking up CWE-{cwe_id}: {e}")

                    # Update/Create weakness
                    weakness_inst, created = Weakness.objects.update_or_create(
                        cve=cve,
                        cwe=cwe_instance,
                        defaults={
                            'source': weakness['source'],
                            'type': weakness['type'],
                        }
                    )
                    if created:
                        try:
                            logger.info(f"Added weakness {weakness_inst.cwe.id} for {cve.id}")
                        except AttributeError:

                            # No CWE assigned
                            if not weakness_inst.cwe:
                                logger.info(f"Added weakness {desc['value']} for {cve.id}")

            for config in cve_info.get('configurations', []):
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        configuration, created = Configuration.objects.update_or_create(
                            cve=cve,
                            operator=node['operator'],
                            negate=node['negate'],
                            criteria=cpe_match['criteria'],
                            defaults={
                                'version_end_excluding': cpe_match.get('versionEndExcluding'),
                                'version_end_including': cpe_match.get('versionEndIncluding'),
                            }
                        )
                        if created:
                            logger.info(f"Added config {configuration.criteria} for {cve.id}")

            for ref in cve_info.get('references', []):
                reference, created = Reference.objects.update_or_create(
                    cve=cve,
                    url=ref['url'],
                    defaults={
                        'source': ref['source'],
                        'tags': ','.join(ref.get('tags', [])),
                    }
                )
                if created:
                    logger.info(f"Added reference {reference.url} for {cve.id}")


def convert_mitre_cwe(mitre_data: dict):
    """
    Convert MITRE CWE data to the database model.
    Handles both weaknesses and categories.
    """

    # Determine which results to use (Weaknesses or Categories)
    if 'Weaknesses' in mitre_data:
        results = mitre_data['Weaknesses']
        cwe_type = 'weakness'
    elif 'Categories' in mitre_data:
        logger.info(f"Weaknesses not found. Switching to category endpoint.")
        results = mitre_data['Categories']
        cwe_type = 'category'
    elif 'Views' in mitre_data:
        logger.info(f"Weaknesses not found. Switching to view endpoint.")
        results = mitre_data['Views']
        cwe_type = 'view'
    else:
        results = []
        cwe_type = None

    # Iterate over all entries in the results
    for entry in results:
        cwe_id = int(entry['ID'])
        name = entry.get('Name', '')
        abstraction = entry.get('Abstraction', None)
        structure = entry.get('Structure', None)
        status = entry.get('Status', '')
        diagram = entry.get('Diagram', None)
        likelihood_of_exploit = entry.get('LikelihoodOfExploit', '')

        # Handle description
        description = ''
        if cwe_type == 'weakness':
            description = entry.get('Description', None)
        elif cwe_type == 'category':
            description = entry.get('Summary', None)
        elif cwe_type == 'view':
            description = entry.get('Objective', None)

        # Extract scope, impact, and note from CommonConsequences (if applicable)
        scope_list = []
        impact_list = []
        note = ''

        common_consequences = entry.get('CommonConsequences', [])
        if common_consequences:
            for consequence in common_consequences:
                scope_list.extend(consequence.get('Scope', []))
                impact_list.extend(consequence.get('Impact', []))
                note = consequence.get('Note', '')

        scope = ', '.join(scope_list) if scope_list else ''
        impact = ', '.join(impact_list) if impact_list else ''

        # Update or create CWE in the database
        cwe, created = CWE.objects.update_or_create(
            id=cwe_id,
            defaults={
                'name': name,
                'abstraction': abstraction,
                'structure': structure,
                'status': status,
                'diagram': diagram,
                'description': description,
                'likelihood_of_exploit': likelihood_of_exploit,
                'scope': scope,
                'impact': impact,
                'note': note,
                'cwe_type': cwe_type
            }
        )

        if created:
            logger.info(f"Created CWE entry: {cwe.name} (ID: {cwe_id})")


def convert_nist_history(history_data: dict):
    for change in history_data.get('cveChanges', []):
        change_info = change['change']

         # Convert naive datetime to timezone-aware datetime
        created_at = datetime.strptime(change_info['created'], '%Y-%m-%dT%H:%M:%S.%f')
        if timezone.is_naive(created_at):
            created_at = timezone.make_aware(created_at, timezone.get_current_timezone())

        cve_change, created = CVEChange.objects.update_or_create(
            cve_id=change_info['cveId'],
            cve_change_id=change_info['cveChangeId'],
            defaults={
                'event_name': change_info['eventName'],
                'source_identifier': change_info['sourceIdentifier'],
                'created_at': created_at,
            }
        )

        if cve_change:
            for detail in change_info.get('details', []):
                _, created = ChangeDetail.objects.update_or_create(
                    cve_change=cve_change,
                    action=detail['action'],
                    type=detail['type'],
                    defaults={
                        'old_value': detail.get('oldValue', None),
                        'new_value': detail.get('newValue', None),
                    }
                )
                if created:
                    logger.info(f"Added change detail for {change_info['cveId']}")

def pick_reference(references):
    """
    Given a list of Reference instances, prioritize and return the best one based on tags.
    The tags are assumed to be comma-separated in the `tags` field.

    Parameters:
        references (QuerySet): A queryset of Reference instances to evaluate.

    Returns:
        Reference: The reference with the highest priority based on tags.
    """

    # Define a priority list for tags (from highest to lowest priority)
    tag_priority = [
        "Vendor Advisory",
        "Patch",
        "Mitigation",
        "US Government Resource",
        "Third Party Advisory",
        "Press/Media Coverage",
        "VDB Entry",
        "Exploit",
        "Issue Tracking",
        "Release Notes",
        "Product",
        "Technical Description"
        "Permissions Required"
        "Mailing List",
        "Not Applicable",
        None,
        "Broken Link"
    ]

    def get_reference_score(reference):
        """
        Given a reference instance, return its score based on the tags it contains.
        """
        if reference.tags:
            # Split the tags by commas and strip any leading/trailing spaces
            tags = [tag.strip() for tag in reference.tags.split(",")]

            # Iterate over the tag priority list and assign the highest ranking tag to this reference
            for priority, tag in enumerate(tag_priority):
                if tag in tags:
                    return priority

        # If no relevant tags are found, assign a very low priority score
        return len(tag_priority)

    # Sort the references by their tag score (lower score = higher priority)
    best_reference = min(references, key=get_reference_score, default=None)

    return best_reference
