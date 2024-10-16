"""
!/usr/bin/env python3
 -*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        admin.py
Purpose:     Register models and admin views for the Biotremor application
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     10/15/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import *

@admin.register(CVE)
class CVEAdmin(admin.ModelAdmin):
    """
    Admin interface for managing Common Vulnerabilities and Exposures (CVE).
    """
    list_display = (
        'id', 'source_identifier', 'published', 'last_modified',
        'vuln_status', 'cisa_exploit_add', 'cisa_action_due',
        'cisa_required_action', 'cisa_vulnerability_name'
    )
    search_fields = ('id', 'source_identifier', 'vuln_status', 'cisa_vulnerability_name')


@admin.register(Description)
class DescriptionAdmin(admin.ModelAdmin):
    """
    Admin interface for managing descriptions associated with CVEs.
    """
    list_display = ('cve', 'lang', 'value')
    search_fields = ('cve__id', 'lang')


@admin.register(CVSSMetricV31)
class CVSSMetricV31Admin(admin.ModelAdmin):
    """
    Admin interface for managing CVSS v3.1 metrics.
    """
    list_display = ('cve', 'source', 'type', 'vector_string', 'base_score', 'base_severity')
    search_fields = ('cve__id', 'source', 'type')


@admin.register(CVSSMetricV20)
class CVSSMetricV20Admin(admin.ModelAdmin):
    """
    Admin interface for managing CVSS v2.0 metrics.
    """
    list_display = (
        'cve', 
        'source', 
        'vector_string', 
        'base_score', 
        'severity'
    )
    search_fields = ('cve__id', 'source', 'type')


@admin.register(CWE)
class CWEAdmin(admin.ModelAdmin):
    """
    Admin interface for managing Common Weakness Enumeration (CWE) entries.
    """
    list_display = ('id', 'name', 'abstraction', 'structure', 'status', 'likelihood_of_exploit')
    search_fields = ('id', 'name', 'abstraction', 'structure', 'status')


@admin.register(Weakness)
class WeaknessAdmin(admin.ModelAdmin):
    """
    Admin interface for managing weaknesses linked to CVEs.
    """
    list_display = ('cve', 'source', 'type', 'cwe')
    search_fields = ('cve__id', 'source', 'type', 'cwe__id', 'cwe__name')


@admin.register(Configuration)
class ConfigurationAdmin(admin.ModelAdmin):
    """
    Admin interface for managing configuration settings related to CVEs.
    """
    list_display = (
        'cve', 'operator', 'negate',
        'criteria', 'version_end_excluding',
        'version_end_including'
    )
    search_fields = ('cve__id', 'operator', 'criteria')


class TagListFilter(admin.SimpleListFilter):
    """
    Create a custom filter for the tags field in the admin interface.
    """
    title = _('Tags')
    parameter_name = 'tags'

    def lookups(self, request, model_admin):
        """
        Extract unique tags from the comma-separated list and provide them as filter options.
        Also includes a 'No Tags' option for references without tags.

        Args:
            request (HttpRequest): The current request object.
            model_admin (ModelAdmin): The model admin instance.

        Returns:
            list: A list of tuples containing tag options for filtering.
        """
        tags = set()
        references = model_admin.model.objects.all()

        # Gather unique tags from all references
        for reference in references:
            if reference.tags:
                # Split tags by commas and strip any whitespace
                tags.update(tag.strip() for tag in reference.tags.split(','))

        # Add 'No Tags' option
        lookups = [(tag, tag) for tag in sorted(tags)]
        lookups.append(('__none', _('No Tags')))  # Special option for no tags
        return lookups

    def queryset(self, request, queryset):
        """
        Filter the queryset based on the selected tag.

        Args:
            request (HttpRequest): The current request object.
            queryset (QuerySet): The queryset to filter.

        Returns:
            QuerySet: The filtered queryset.
        """
        if self.value() == '__none':
            # Filter references with no tags or empty tags
            return queryset.filter(tags__isnull=True) | queryset.filter(tags='')
        elif self.value():
            # Filter by tag (in cases of multiple tags, use __contains)
            return queryset.filter(tags__icontains=self.value())
        return queryset


@admin.register(Reference)
class ReferenceAdmin(admin.ModelAdmin):
    """
    Admin interface for managing external references linked to CVEs.
    """
    list_display = ('cve', 'url_link', 'source', 'tags')
    search_fields = ('cve__id', 'url', 'source')
    list_filter = (TagListFilter,)

    def url_link(self, obj):
        """
        Make the URL clickable and open in a new tab.

        Args:
            obj (Reference): The reference object being rendered.

        Returns:
            SafeString: A clickable HTML link to the reference URL.
        """
        return format_html('<a href="{}" target="_blank">{}</a>', obj.url, obj.url)
    url_link.short_description = 'URL'


@admin.register(CVEChange)
class CVEChangeAdmin(admin.ModelAdmin):
    """
    Admin interface for tracking changes to CVE entries.
    """
    list_display = ('cve', 'event_name', 'cve_change_id', 'source_identifier', 'created_at')
    search_fields = ('cve__id', 'event_name', 'source_identifier')


@admin.register(ChangeDetail)
class ChangeDetailAdmin(admin.ModelAdmin):
    """
    Admin interface for viewing details of changes made to CVEs.
    """
    list_display = ('cve_change', 'action', 'type', 'old_value', 'new_value')
    search_fields = ('cve_change__cve__id', 'action', 'type')


@admin.register(EPSS)
class EPSSAdmin(admin.ModelAdmin):
    """
    Admin interface for managing Exploit Prediction Scoring System (EPSS) scores.
    """
    list_display = ('cve', 'score', 'percentile', 'date')
    search_fields = ('cve',)


@admin.register(Priority)
class PriorityAdmin(admin.ModelAdmin):
    """
    Admin interface for managing priority levels associated with vulnerabilities.
    """
    list_display = ('id', 'name')


@admin.register(CVERating)
class CVERatingAdmin(admin.ModelAdmin):
    """
    Admin interface for managing ratings assigned to CVEs.
    """
    list_display = ('cve', 'priority', 'method', 'source', 'updated', 'created_at')
    search_fields = ('cve__id', 'priority__name', 'method', 'source')
    list_filter = ('method', 'priority', 'source')


@admin.register(PreProcessedCVE)
class PreProcessedCVEAdmin(admin.ModelAdmin):
    """
    Admin interface for viewing processed CVE data.
    """
    list_display = (
        'cve',
        'rating',
        'cvss_v31_base_score',
        'cvss_v31_exploitability_score',
        'cvss_v31_impact_score',
        'epss_score',
        'epss_percentile',
    )
    search_fields = ('cve__id', 'rating__name')
    list_filter = ('rating',)

    def has_add_permission(self, request):
        """
        Deny permission to add new PreProcessedCVE entries.

        Args:
            request (HttpRequest): The current request object.

        Returns:
            bool: Always returns False.
        """
        return False

    def has_change_permission(self, request, obj=None):
        """
        Deny permission to change existing PreProcessedCVE entries.

        Args:
            request (HttpRequest): The current request object.
            obj (PreProcessedCVE, optional): The object being changed. Defaults to None.

        Returns:
            bool: Always returns False.
        """
        return False
