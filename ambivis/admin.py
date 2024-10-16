"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        admin.py
Purpose:     Register models and admin views required by the Discord Bot
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""

from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from .models import *

@admin.register(DiscordUser)
class DiscordUserAdmin(admin.ModelAdmin):
    """
    Admin view for managing DiscordUser models.
    
    Handles universal user information, including bot status.
    Guild-specific fields like avatar and display_name are managed in DiscordGuildMemberAdmin.
    """
    list_display = ('name', 'global_name', 'bot')
    search_fields = ('name', 'global_name', 'id')
    list_filter = ('bot',)


@admin.register(DiscordGuildMember)
class DiscordGuildMemberAdmin(admin.ModelAdmin):
    """
    Admin view for managing DiscordGuildMember models.
    
    Handles guild-specific user information such as display name and avatar.
    """
    list_display = ('avatar_thumbnail', 'display_name', 'pending', 'user_name', 'guild_name')

    def avatar_thumbnail(self, obj):
        """
        Display the user's avatar as a thumbnail.
        
        Args:
            obj (DiscordGuildMember): The DiscordGuildMember instance.

        Returns:
            Safe HTML string containing the avatar image or a placeholder if none exists.
        """
        if obj.avatar: 
            return format_html(f'<img src="{obj.avatar}" width="36" height="36" style="border-radius: 50%;"/>')
        return mark_safe('<span>No Avatar</span>')
    avatar_thumbnail.short_description = 'Avatar'

    def user_name(self, obj):
        """
        Display the associated DiscordUser's name.

        Args:
            obj (DiscordGuildMember): The DiscordGuildMember instance.

        Returns:
            str: The name of the associated DiscordUser.
        """
        return obj.user_id.name
    user_name.short_description = 'User'

    def guild_name(self, obj):
        """
        Display the name of the guild this user belongs to.

        Args:
            obj (DiscordGuildMember): The DiscordGuildMember instance.

        Returns:
            str: The name of the associated DiscordGuild.
        """
        return obj.guild_id.name
    guild_name.short_description = 'Guild'


@admin.register(DiscordGuild)
class DiscordGuildAdmin(admin.ModelAdmin):
    """
    Admin view for managing DiscordGuild models.
    
    Handles guild information including the owner.
    """
    list_display = ('icon_thumbnail', 'name', 'owner_name')

    def icon_thumbnail(self, obj):
        """
        Display the guild's icon as a thumbnail.

        Args:
            obj (DiscordGuild): The DiscordGuild instance.

        Returns:
            Safe HTML string containing the icon image or a placeholder if none exists.
        """
        if obj.icon:
            return format_html(f'<img src="{obj.icon}" width="36" height="36" style="border-radius: 50%;"/>')
        return mark_safe('<span>No Icon</span>')
    icon_thumbnail.short_description = 'Icon'

    def owner_name(self, obj):
        """
        Display the name of the guild's owner (DiscordUser model).

        Args:
            obj (DiscordGuild): The DiscordGuild instance.

        Returns:
            str: The name of the owner as a DiscordUser.
        """
        return obj.owner.name
    owner_name.short_description = 'Owner'


@admin.register(DiscordRole)
class DiscordRoleAdmin(admin.ModelAdmin):
    """
    Admin view for managing DiscordRole models.
    
    Provides an interface to manage roles associated with guilds.
    """
    list_display = ('name', 'guild_info',)
    search_fields = ('name', 'guild_id__name')

    def get_queryset(self, request):
        """
        Customize the queryset to include related guild data.

        Args:
            request (HttpRequest): The request object.

        Returns:
            QuerySet: The customized queryset including related guilds.
        """
        queryset = super().get_queryset(request)
        return queryset.select_related('guild_id')

    def guild_info(self, obj):
        """
        Display the name of the guild associated with the role along with its icon.

        Args:
            obj (DiscordRole): The DiscordRole instance.

        Returns:
            Safe HTML string containing the guild icon and name.
        """
        guild_name = obj.guild_id.name
        guild_icon = obj.guild_id.icon
        icon_html = (
            f'<img src="{guild_icon}" width="24" height="24" style="border-radius: 50%; margin-right: 5px;" />'
            if guild_icon else '<span>No Icon</span>'
        )
        return format_html(f'{icon_html}{guild_name}')
    guild_info.short_description = 'Guild'


@admin.register(DiscordChannel)
class DiscordChannelAdmin(admin.ModelAdmin):
    """
    Admin view for managing DiscordChannel models.
    
    Provides an interface to manage channels within a guild.
    """
    list_display = ('name', 'topic', 'guild_info',)
    search_fields = ('name', 'topic', 'id')
    list_filter = ('guild_id',)

    def guild_info(self, obj):
        """
        Display the name of the guild associated with the channel along with its icon.

        Args:
            obj (DiscordChannel): The DiscordChannel instance.

        Returns:
            Safe HTML string containing the guild icon and name.
        """
        guild_name = obj.guild_id.name
        guild_icon = obj.guild_id.icon
        icon_html = (
            f'<img src="{guild_icon}" width="24" height="24" style="border-radius: 50%; margin-right: 5px;" />'
            if guild_icon else '<span>No Icon</span>'
        )
        return format_html(f'{icon_html}{guild_name}')
    guild_info.short_description = 'Guild'


@admin.register(RSSSource)
class RSSSourceAdmin(admin.ModelAdmin):
    """
    Admin view for managing RSSSource models.
    
    Provides an interface for managing RSS feed sources.
    """
    list_display = ('name', 'url', 'last_updated', 'enabled', 'color')
    search_fields = ('name', 'url')
    list_filter = ('enabled',)


@admin.register(RSSEntry)
class RSSEntryAdmin(admin.ModelAdmin):
    """
    Admin view for managing RSSEntry models.
    
    Provides an interface for managing entries from RSS feeds.
    """
    list_display = ('title', 'link', 'author', 'guid', 'published_date', 'source', 'awaiting_delivery')
    search_fields = ('title', 'link', 'author', 'description')
    list_filter = ('source', 'published_date')
    ordering = ('-published_date',)


@admin.register(BotTask)
class BotTaskAdmin(admin.ModelAdmin):
    """
    Admin view for managing BotTask models.
    
    Provides an interface for managing background tasks associated with the bot.
    """
    list_display = ('id', 'name', 'created_at', 'processed', 'is_processed')
    list_filter = ('processed', 'created_at')
    search_fields = ('name', 'kwargs')
    list_editable = ('processed',)
    ordering = ('-created_at',)

    def is_processed(self, obj):
        """
        Indicate whether the task has been processed.

        Args:
            obj (BotTask): The BotTask instance.

        Returns:
            bool: True if processed, otherwise False.
        """
        return obj.processed is not None
    
    is_processed.boolean = True
    is_processed.short_description = 'Processed'
