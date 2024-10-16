"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        models.py
Purpose:     Define models required by the Biotremor
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     9/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from django.db import models
from django.core.exceptions import ValidationError

class CVE(models.Model):
    """
    Represents a Common Vulnerabilities and Exposures (CVE) entry.
    """
    id = models.CharField(max_length=20, primary_key=True)
    source_identifier = models.CharField(max_length=100)
    published = models.DateTimeField()
    last_modified = models.DateTimeField()
    vuln_status = models.CharField(max_length=50)
    cisa_exploit_add = models.DateField(blank=True, null=True)
    cisa_action_due = models.DateField(blank=True, null=True)
    cisa_required_action = models.TextField(blank=True, null=True)
    cisa_vulnerability_name = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        """
        Customize model fields
        """
        verbose_name_plural = "CVE Records"


class CWE(models.Model):
    """
    Represents a Common Weakness Enumeration (CWE) entry.
    """
    CWE_TYPES = [
        ('weakness', 'Weakness'),
        ('category', 'Category'),
        ('view', 'View'),
    ]

    # CWE fields
    id = models.CharField(max_length=10, primary_key=True)
    name = models.CharField(max_length=255)
    abstraction = models.CharField(max_length=50, blank=True, null=True)
    structure = models.CharField(max_length=50, blank=True, null=True)
    status = models.CharField(max_length=50)
    diagram = models.URLField(max_length=500, blank=True, null=True)
    description = models.TextField(500)
    likelihood_of_exploit = models.CharField(max_length=50, blank=True, null=True)
    cwe_type = models.CharField(choices=CWE_TYPES)

    # Scope and impact can be comma-separated values
    scope = models.CharField(max_length=255, blank=True, null=True)
    impact = models.CharField(max_length=355, blank=True, null=True)
    note = models.TextField(blank=True, null=True)

    class Meta:
        """
        Customize meta-data
        """
        verbose_name_plural = "CWEs"

    def __str__(self):
        return f"CWE-{self.id}: {self.name}"


class Description(models.Model):
    """
    Represents a description associated with a CVE entry.
    """
    cve = models.ForeignKey(CVE, related_name='descriptions', on_delete=models.CASCADE)
    lang = models.CharField(max_length=10)
    value = models.TextField()

    class Meta:
        """
        Customize model fields
        """
        unique_together = ('cve', 'value')


class CVSSMetricV31(models.Model):
    """
    Represents CVSS (Common Vulnerability Scoring System) version 3.1 metrics for a CVE.
    """
    cve = models.OneToOneField(CVE, related_name='cvss_metrics_v3', on_delete=models.CASCADE)
    source = models.CharField(max_length=100)
    type = models.CharField(max_length=50)
    vector_string = models.CharField(max_length=100)
    attack_vector = models.CharField(max_length=50)
    attack_complexity = models.CharField(max_length=50)
    privileges_required = models.CharField(max_length=50)
    user_interaction = models.CharField(max_length=50)
    scope = models.CharField(max_length=50)
    confidentiality_impact = models.CharField(max_length=50)
    integrity_impact = models.CharField(max_length=50)
    availability_impact = models.CharField(max_length=50)
    base_score = models.FloatField()
    base_severity = models.CharField(max_length=50)
    exploitability_score = models.FloatField()
    impact_score = models.FloatField()

    class Meta:
        """
        Customize model fields
        """
        verbose_name_plural = "CVSS 3.1 Metrics"


class CVSSMetricV20(models.Model):
    """
    Represents CVSS version 2.0 metrics for a CVE.
    """
    cve = models.OneToOneField(CVE, related_name='cvss_metrics_v2', on_delete=models.CASCADE)
    source = models.CharField(max_length=100)
    type = models.CharField(max_length=50)
    vector_string = models.CharField(max_length=100)
    access_vector = models.CharField(max_length=50)
    access_complexity = models.CharField(max_length=50)
    authentication = models.CharField(max_length=50)
    confidentiality_impact = models.CharField(max_length=50)
    integrity_impact = models.CharField(max_length=50)
    availability_impact = models.CharField(max_length=50)
    base_score = models.FloatField()
    severity = models.CharField(max_length=50)
    exploitability_score = models.FloatField()
    impact_score = models.FloatField()

    class Meta:
        """
        Customize model fields
        """
        verbose_name_plural = "CVSS 2.0 Metrics"


class Weakness(models.Model):
    """
    Represents a weakness associated with a CVE.
    """
    cve = models.ForeignKey(CVE, related_name='weaknesses', on_delete=models.CASCADE)
    source = models.CharField(max_length=100)
    type = models.CharField(max_length=50)
    cwe = models.ForeignKey(
        CWE,
        related_name='weaknesses',
        on_delete=models.SET_NULL,
        blank=True,
        null=True
    )

    class Meta:
        """
        Customize model fields
        """
        unique_together = ('cve', 'cwe')


class Configuration(models.Model):
    """
    Represents a configuration associated with a CVE.
    """
    cve = models.ForeignKey(CVE, related_name='configurations', on_delete=models.CASCADE)
    operator = models.CharField(max_length=10)
    negate = models.BooleanField()
    criteria = models.CharField(max_length=255)
    version_end_excluding = models.CharField(max_length=50, null=True, blank=True)
    version_end_including = models.CharField(max_length=50, null=True, blank=True)


class Reference(models.Model):
    """
    Represents a reference link associated with a CVE.
    """
    cve = models.ForeignKey(CVE, related_name='references', on_delete=models.CASCADE)
    url = models.URLField(max_length=400)
    source = models.CharField(max_length=100)
    tags = models.CharField(max_length=255)

    class Meta:
        """
        Customize model fields
        """
        unique_together = ('cve', 'url')


class CVEChange(models.Model):
    """
    Represents a change record associated with a CVE.
    """
    cve = models.ForeignKey(CVE, related_name='changes', on_delete=models.CASCADE)
    event_name = models.CharField(max_length=100)
    cve_change_id = models.CharField(max_length=50, primary_key=True)
    source_identifier = models.CharField(max_length=100)
    created_at = models.DateTimeField()

    class Meta:
        """
        Customize model fields
        """
        verbose_name_plural = "CVE Changes"


class ChangeDetail(models.Model):
    """
    Represents detailed information about a change associated with a CVEChange.
    """
    cve_change = models.ForeignKey(CVEChange, related_name='details', on_delete=models.CASCADE)
    action = models.CharField(max_length=50)
    type = models.CharField(max_length=50)
    old_value = models.TextField(null=True, blank=True)
    new_value = models.TextField(null=True, blank=True)


class EPSS(models.Model):
    """
    Represents EPSS (Exploit Prediction Scoring System) metrics for a CVE.
    """
    cve = models.OneToOneField(CVE, related_name='epss', on_delete=models.CASCADE)
    score = models.FloatField()
    percentile = models.FloatField()
    date = models.DateField()

    class Meta:
        """
        Customize model fields
        """
        verbose_name_plural = "EPSS Metrics"


class Priority(models.Model):
    """
    Represents the priority rating for a CVE.
    """
    PRIORITY_IDs = [ (n, n) for n in range(5) ]
    PRIORITY_NAMES = [
        ('UNKNOWN', 'UNKNOWN'),
        ('LOW', 'LOW'),
        ('MEDIUM', 'MEDIUM'),
        ('HIGH', 'HIGH'),
        ('CRITICAL', 'CRITICAL'),
    ]

    id = models.IntegerField(choices=PRIORITY_IDs, primary_key=True)
    name = models.CharField(max_length=10, choices=PRIORITY_NAMES, unique=True)

    def __str__(self):
        return self.name

    class Meta:
        """
        Customize model fields
        """
        verbose_name_plural = "Priorities"


class CVERating(models.Model):
    """
    Represents a rating associated with a CVE, determining its priority.
    """
    METHOD_CHOICES = [
        ('auto', 'Auto'),
        ('manual', 'Manual'),
    ]

    cve = models.OneToOneField('CVE', on_delete=models.CASCADE)
    priority = models.ForeignKey('Priority', on_delete=models.CASCADE)
    method = models.CharField(max_length=6, choices=METHOD_CHOICES)
    updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    source = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.cve} - {self.priority} - {self.method}"

    class Meta:
        """
        Customize model fields
        """
        verbose_name_plural = "CVE Ratings"


class PreProcessedCVE(models.Model):
    """
    Stores pre-processed, machine learning ready data for each CVE that has a manually rated priority.
    """
    ONE_HOT = [
        (0, "False"),
        (1, "True")
    ]

    # CVE
    cve = models.OneToOneField('CVE', on_delete=models.CASCADE)
    cisa_exploit_add = models.IntegerField(choices=ONE_HOT)
    cve_published_epoch = models.IntegerField(blank=True, null=True)

    # Weakness
    weakness_cwe_encoded = models.IntegerField()

    # CVERating (Must allow null for predicting)
    rating = models.ForeignKey('Priority', on_delete=models.CASCADE, blank=True, null=True)

    # CVSS 3.1
    cvss_v31_base_score = models.FloatField()
    cvss_v31_exploitability_score = models.FloatField()
    cvss_v31_impact_score = models.FloatField()
    cvss_v31_attack_vector_encoded = models.IntegerField()
    cvss_v31_attack_complexity_encoded = models.IntegerField()
    cvss_v31_privileges_required_encoded = models.IntegerField()
    cvss_v31_user_interaction_encoded = models.IntegerField()
    cvss_v31_scope_encoded = models.IntegerField()
    cvss_v31_confidentiality_impact_encoded = models.IntegerField()
    cvss_v31_integrity_impact_encoded = models.IntegerField()
    cvss_v31_availability_impact_encoded = models.IntegerField()

    # CVSS 2.0
    cvss_v20_base_score = models.FloatField()
    cvss_v20_exploitability_score = models.FloatField()
    cvss_v20_impact_score = models.FloatField()
    cvss_v20_access_vector_encoded = models.IntegerField()
    cvss_v20_access_complexity_encoded = models.IntegerField()
    cvss_v20_authentication_encoded = models.IntegerField()
    cvss_v20_confidentiality_impact_encoded = models.IntegerField()
    cvss_v20_integrity_impact_encoded = models.IntegerField()
    cvss_v20_availability_impact_encoded = models.IntegerField()

    # EPSS
    epss_score = models.FloatField()
    epss_percentile = models.FloatField()

    # One-hot encoded Reference tags (use IntegerField with 0/1 values)
    has_patch = models.IntegerField(choices=ONE_HOT, default=0)
    has_mitigation = models.IntegerField(choices=ONE_HOT, default=0)
    has_us_gov_resource = models.IntegerField(choices=ONE_HOT, default=0)
    has_press_media_coverage = models.IntegerField(choices=ONE_HOT, default=0)
    has_exploit = models.IntegerField(choices=ONE_HOT, default=0)

    def clean(self):
        """
        Custom validation to ensure the associated CVE has a CVERating with method 'manual'.
        """
        if not hasattr(self, 'cve'):
            raise ValidationError("CVE must be set.")

        # Check for CVERating with method 'manual'
        if not CVERating.objects.filter(cve=self.cve, method='manual').exists():
            raise ValidationError(f"The CVE '{self.cve.id}' must have a CVERating with method 'manual'.")

    def save(self, *args, **kwargs):
        """
        Override the save method to call clean before saving.
        """
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"PreProcessed: {self.cve.id} - Rating: {self.rating}"

    class Meta:
        """
        Customize model fields
        """
        verbose_name_plural = "Pre-Processed CVEs"
