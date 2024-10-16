"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        views.py
Purpose:     Define views for biotremor django app
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
# API
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView

# App configs
from core.utils.format import validate_cve
from core.models import Credential

from .models import CVERating, Description, EPSS, Weakness, Reference, Priority
from .apps import group_name
from .serializers import CVERatingSerializer
from .tasks import predict_priority
from .utils.system import cve_lookup


class inBioTremorGroup(BasePermission):
    """
    Custom permissions for Ambivis API
    """

    def has_permission(self, request, view):
        """
        Check if the user is authenticated and belongs to the specified group
        """
        return request.user.is_authenticated and request.user.groups.filter(name=group_name).exists()


class Lookup(APIView):
    """
    API returns CVE data for a specified CVE ID.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, inBioTremorGroup]

    def post(self, request, *args, **kwargs):
        cve_id = request.data.get('cve_id')
        cve_id = validate_cve(cve_id)
        if not cve_id:
            return Response({"error": "CVE ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the CVE by cve_id
        cve = cve_lookup(
            cve_id,
            nist_api_key=Credential.objects.get(cred_type="key", platform='nist').value
        )

        # Handle case where cve_lookup returns None
        if cve is None:
            return Response({"error": f"No data found for CVE ID {cve_id}"}, status=status.HTTP_404_NOT_FOUND)

        # Get rating
        cve_rating = CVERating.objects.filter(cve=cve).first()
        if not cve_rating:
            cve_rating = predict_priority(cve_id)

        # Get EPSS
        epss = EPSS.objects.filter(cve=cve).first()
        description = Description.objects.filter(lang='en', cve=cve).first()

        # Fetch all associated weaknesses and their corresponding CWEs
        weaknesses = Weakness.objects.filter(cve=cve).select_related('cwe')

        # Create lists to store CWE names and impacts
        weaknesses = Weakness.objects.filter(cve=cve).select_related('cwe')

        # Enumerate weaknesses
        cwe_list = []
        for weakness in weaknesses:
            if weakness.cwe:
                cwe_list.append(f"*{weakness.cwe.name}*: {weakness.cwe.impact}")

        # Fetch references
        all_references = Reference.objects.filter(cve=cve)
        references_list = [ref.url for ref in all_references]

        # Format the published field as ISO 8601 or return None if not available
        published_str = cve.published.isoformat() if cve.published else None

        # Serialize the CVE data
        response = {
            "id": cve.id,
            "cisa_vulnerability_name": cve.cisa_vulnerability_name,
            "priority": [cve_rating.priority.name],
            "rating_method": [cve_rating.method],
            "cisa_exploit_add": ["True"] if cve.cisa_exploit_add else ["False"],
            "published": published_str,
            "description": description.value if description else None,
            "EPSS.score": [epss.score] if epss else [None],
            "EPSS.percentile": [epss.percentile] if epss else [None],
            "weakness": cwe_list,
            "reference": references_list,
        }

        return Response(response, status=status.HTTP_200_OK)


class Rate(APIView):
    """
    API creates or updates priority rating for a given CVE ID.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, inBioTremorGroup]

    def post(self, request, *args, **kwargs):
        """
        Handle post request to the rate API
        """
        cve_id = request.data.get('cve_id')
        priority = request.data.get('priority')
        source = request.data.get('source')

        if not cve_id or priority is None:
            return Response(
                {"error": "CVE ID and priority are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Fetch the CVE by cve_id
        cve = cve_lookup(cve_id, nist_api_key=Credential.objects.get(cred_type="key", platform='nist').value)

        # Handle case where cve_lookup returns None
        if not cve:
            return Response(
                {"error": f"No data found for CVE ID {cve_id}"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Fetch the priority object
        priority = Priority.objects.filter(id=priority).first()
        if not priority:
            return Response({"error": "Invalid priority"}, status=status.HTTP_404_NOT_FOUND)

        # Check if a rating already exists, update it; otherwise, create a new one
        cve_rating, created = CVERating.objects.update_or_create(
            cve=cve,
            defaults={'priority': priority, 'method': 'manual', 'source': source}
        )

        # Serialize the CVE Rating
        serializer = CVERatingSerializer(cve_rating)
        if created:
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.data, status=status.HTTP_200_OK)
