"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        tests.py
Purpose:     For development purposes only. Execute functions wihin the Ambivis app.
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/30/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from .tasks import prep_model, train_model, predict_priority, backfill_weakness_cwe

def prep():
    """
    Test fetch_rss_entries when no sources are specified and initial is false.
    """
    prep_model(train=False)

def train():
    """
    Test fetch_rss_entries when no sources are specified and initial is false.
    """
    train_model()

def predict():
    """
    Test fetch_rss_entries when no sources are specified and initial is false.
    """
    test_cves = [
        'CVE-2024-3516', # Should return already rated (manual)
        'CVE-2024-8942',
        'CVE-2024-8941'
    ]

    for cve in test_cves:
        predict_priority(cve)

def populate_cwe():
    """
    Test fetch_rss_entries when no sources are specified and initial is false.
    """
    backfill_weakness_cwe()
