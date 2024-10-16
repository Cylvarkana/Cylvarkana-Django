"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        models.py
Purpose:     Define models required by the Ambivis Discord Bot
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from django.db import models
from django.db import transaction

from .tasks import fetch_rss_entries


class DiscordUser(models.Model):
    """
    Manage Discord Users
    """
    id = models.CharField(max_length=24, primary_key=True)
    global_name = models.CharField(max_length=64, blank=True, null=True)
    name = models.CharField(max_length=64)
    bot = models.BooleanField()


class DiscordGuild(models.Model):
    """
    Manage bot guilds
    """
    id = models.CharField(max_length=24, primary_key=True)
    name = models.CharField(max_length=64)
    icon = models.URLField(max_length=124)
    owner = models.ForeignKey(DiscordUser, on_delete=models.PROTECT, related_name='owner')


class DiscordRole(models.Model):
    """
    Manage Discord Roles
    """
    id = models.CharField(max_length=24, primary_key=True)
    name = models.CharField(max_length=64)
    guild_id = models.ForeignKey(DiscordGuild, on_delete=models.CASCADE, related_name='roles')

class DiscordGuildMember(models.Model):
    """
    Guild Members
    """
    user_id = models.ForeignKey(DiscordUser, on_delete=models.CASCADE, related_name='guild_memberships')
    guild_id = models.ForeignKey(DiscordGuild, on_delete=models.CASCADE, related_name='members')
    roles = models.ManyToManyField(DiscordRole, related_name='member_roles', blank=True)
    display_name = models.CharField(max_length=64)
    pending = models.BooleanField()
    avatar = models.URLField(max_length=124, blank=True, null=True)
    
    class Meta:
        """
        Customize model fields
        """
        unique_together = ("user_id", "guild_id")


class DiscordChannel(models.Model):
    """
    Track Discord channels
    """
    id = models.CharField(max_length=255, primary_key=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    topic = models.TextField(blank=True, null=True)
    guild_id = models.ForeignKey(DiscordGuild, on_delete=models.CASCADE, related_name='channels')

    def __str__(self):
        """
        Set default value of object return
        """
        return self.name if self.name else self.discord_channel_id


class RSSSource(models.Model):
    """
    Manage RSS Feed sources
    """
    COLOR_CHOICES = [
        ('#FF0000', 'Red'),
        ('#00FF00', 'Green'),
        ('#0000FF', 'Blue'),
        ('#FFFF00', 'Yellow'),
        ('#FF00FF', 'Magenta'),
        ('#00FFFF', 'Cyan'),
        ('#000000', 'Black'),
        ('#FFFFFF', 'White'),
        ('#FFD700', 'Gold')
    ]
    
    url = models.URLField(unique=True)
    name = models.CharField(max_length=255, unique=True)
    last_updated = models.DateTimeField(auto_now=True)
    enabled = models.BooleanField(default=True)
    discord_channels = models.ManyToManyField(DiscordChannel, related_name='rss_feed_sources', blank=True)
    color = models.CharField(
        max_length=7,
        choices=COLOR_CHOICES,
        default='#00FF00',
    )

    def __str__(self):
        """
        Set default value of object return
        """
        return self.name

    class Meta:
        """
        Customize model fields
        """
        verbose_name_plural = "RSS sources"

    def save(self, *args, **kwargs):
        """
        Dispatch celery task to auto-populate RSS feed entries upon creation
        """
        is_new = self.pk is None  # Check if the instance is being created

        super().save(*args, **kwargs)
        if is_new and self.enabled:
            transaction.on_commit(lambda: fetch_rss_entries.apply_async(
                args=[[self.name]],
                kwargs={'initial': True}
            ))


class RSSEntry(models.Model):
    """
    Track RSS entries
    """
    source = models.ForeignKey(RSSSource, on_delete=models.CASCADE, related_name='entries')
    title = models.CharField(max_length=255)
    author = models.CharField(max_length=255, null=True, blank=True)
    link = models.URLField(null=True, blank=True)
    enclosure = models.URLField(null=True, blank=True)
    description = models.TextField(blank=True, null=True)
    published_date = models.DateTimeField()
    guid = models.CharField(max_length=255, unique=True)
    awaiting_delivery = models.BooleanField(default=True)

    class Meta:
        """
        Customize model fields
        """
        verbose_name_plural = "RSS entries"

    def __str__(self):
        """
        Set default value of object return
        """
        return self.title


class BotTask(models.Model):
    """
    Model to represent tasks for the Discord bot to process.
    """
    id = models.AutoField(primary_key=True) 
    name = models.CharField(max_length=255)
    args = models.JSONField(null=True, blank=True)
    kwargs = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    processed = models.DateTimeField(null=True, blank=True, default=None)

    def __str__(self):
        return f"BotTask: {self.name} - Processed: {self.processed or 'Pending'}"
