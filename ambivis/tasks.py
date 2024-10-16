"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        tasks.py
Purpose:     Create common tasks for maintaining, updating and other administrative Ambivis services
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/30/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from datetime import timedelta
import feedparser
import html2text
from django.utils import timezone
from celery import shared_task
from .apps import logger


@shared_task(name='Fetch RSS')
def fetch_rss_entries(source_names: list = None, initial: bool = False, send_to_bot: bool=True):
    """
    Celery task to populate RSSEntry and set delivery status when a new RSSSource is created.
    
    :param source_names: List of RSS source names. If None, fetch all RSSSource instances.
    :param initial: Boolean indicating if this is an initial fetch for a new source.
    """
    # Must import in task to avoid circular import
    from .models import RSSSource, RSSEntry
    from .utils.api import fetch_opengraph_data
    
    logger.info(f"Fetching rss entries for source(s) {', '.join(source_names) if source_names else 'all'}: initial = {initial}")
    
    # Fetch all sources enabled if no specific source names are provided
    if not source_names:
        sources = RSSSource.objects.filter(enabled=True)
    else:
        sources = RSSSource.objects.filter(name__in=source_names)
    
    if not sources.exists():
        return  # No sources found, exit the task

    for source in sources:
        # Parse the RSS feed for each source
        feed = feedparser.parse(source.url)

        # Skip invalid or empty feeds
        if 'entries' not in feed or feed.bozo:
            continue

        entries = feed.entries

        for entry in entries:
            
            # Skip entries that are already in the database
            if RSSEntry.objects.filter(guid=entry.guid if 'guid' in entry else entry.id).exists():
                continue
            
            published_date = timezone.now() if 'published_parsed' not in entry else timezone.make_aware(
                timezone.datetime(*entry.published_parsed[:6])
            )

            def get_enclosure(entry):
                """
                Extract enclosures from rss feed
                """
                links = entry.links
                permitted_types = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif']
                for link in links:
                    if link['type'] in permitted_types and 'href' in link:
                        return link['href']
                    
                # Try scraping for image if not included
                if entry.link:
                    og_data = fetch_opengraph_data(entry.link)
                    if og_data:
                        return og_data.get("image", None)
                
                return None

            # Create or update RSSEntry
            enclosure = get_enclosure(entry)
            RSSEntry.objects.update_or_create(
                guid=entry.guid if 'guid' in entry else entry.id,
                defaults={
                    'source': source,
                    'title': entry.title,
                    'link': entry.get('link', None),
                    'author': entry.get('author', None),
                    'description': entry.get('summary', ''),
                    'enclosure': enclosure,
                    'published_date': published_date,
                }
            )

        # Mark entries as delivered for new sources if 'initial' is True
        if initial:
            logger.info(f"Initializing entries for new source: {source.name}")
            rss_entries = RSSEntry.objects.filter(source=source).order_by('-published_date')

            # Mark all but the most recent entry as delivered
            if rss_entries.exists():
                most_recent_entry = rss_entries.first()
                entries_to_mark_as_delivered = rss_entries.exclude(id=most_recent_entry.id)
                entries_to_mark_as_delivered.update(awaiting_delivery=False)
            
    # Call the compile task to send new entries to the Discord bot
    if send_to_bot:
        compile_rss_bottasks.delay()


@shared_task
def compile_rss_bottasks():
    """
    Celery task to create BotTask instances for all RSSEntries awaiting delivery.
    For each RSSEntry, a BotTask is created for every associated DiscordChannel.
    """
    # Lazy import
    from .models import RSSEntry, BotTask

    # Initialize HTML-to-Markdown converter
    converter = html2text.HTML2Text()

    # Ignore links and images which will not render in embed
    converter.ignore_links = True
    converter.ignore_images = True

    # Filter all RSSEntry objects that are awaiting delivery
    entries_awaiting_delivery = RSSEntry.objects.filter(awaiting_delivery=True)
    logger.info(f"Compiling {len(entries_awaiting_delivery)} RSS BotTasks...")

    for entry in entries_awaiting_delivery:
        # Get all associated Discord channels from the entry's source
        discord_channels = entry.source.discord_channels.all()

        # Sanitize HTML to Markdown
        description_markdown = converter.handle(entry.description)

        # Create a BotTask for each associated Discord channel
        for channel in discord_channels:
            # Build the kwargs to be passed into the BotTask
            kwargs = {
                'source': entry.source.name,
                'color': entry.source.color,
                'title': entry.title,
                'author': entry.author,
                'description': description_markdown,
                'enclosure': entry.enclosure,
                'published_date': entry.published_date.strftime('%Y-%m-%d %H:%M:%S'),
                'link': entry.link,
                'channel_id': channel.id
            }

            # Create a new BotTask
            BotTask.objects.create(
                name='send_rss',
                kwargs=kwargs
            )

        # After creating BotTask instances, mark the entry as delivered
        entry.awaiting_delivery = False
        entry.save()

    # Log completion
    message = f"Created BotTasks for {entries_awaiting_delivery.count()} RSSEntries."
    logger.info(message)

    return message

@shared_task(name='Sync Discord Configs')
def que_sync_server():
    """
    Create sync_server BotTask
    """
    from .models import BotTask

    # Check for unprocessed BotTask with the name "sync_server"
    unprocessed_task = BotTask.objects.filter(name="sync_server", processed__isnull=True).first()

    if unprocessed_task:
        # An unprocessed sync_server task exists; do nothing
        return

    # Create a new BotTask for sync_server
    BotTask.objects.create(name="sync_server")


@shared_task(name='Clear Bot Task Logs')
def clear_bot_tasks_logs(days: int=7):
    """
    Delete BotTask records with processed dates older than a certain timeframe.
    Default is 1 week (7 days).
    """
    from .models import BotTask

    cutoff_date = timezone.now() - timedelta(days=days)
    old_tasks = BotTask.objects.filter(processed__lt=cutoff_date)

    # Count the number of tasks to be deleted for logging purposes (optional)
    task_count = old_tasks.count()

    # Delete the old tasks
    old_tasks.delete()

    logger.info(f"Deleted {task_count} BotTask(s) older than {days} days.")
