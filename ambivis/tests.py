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
from .tasks import fetch_rss_entries, compile_rss_bottasks
from .apps import logger
from cylvarkana.settings import *


def test_empty_source_names():
    """
    Test fetch_rss_entries when no sources are specified and initial is false.
    """
    logger.info("Fetching RSS entries for source(s) all: initial = False")
    fetch_rss_entries(source_names=[], initial=False)


def test_rss_compile():
    """
    Testing compilation of RSSEntries into BotTasks.
    """
    logger.info("Testing compilation of RSSEntries into BotTasks")
    compile_rss_bottasks()
