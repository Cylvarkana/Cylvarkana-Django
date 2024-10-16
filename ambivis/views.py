"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        views.py
Purpose:     Define views for the ambivis Django app
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""

# Dashboard views
from django.shortcuts import render
from django.utils import timezone

# API views
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

# App Configs
from core.utils.system import group_required
from .serializers import BotTaskSerializer, BotTaskUpdateSerializer
from .models import (
    DiscordChannel,
    DiscordGuildMember,
    DiscordGuild,
    BotTask,
    RSSSource,
    RSSEntry,
    DiscordUser,
    DiscordRole
)
from .apps import group_name


@group_required(group_name)
def summary(request):
    """
    View to render a summary dashboard for guild statistics.

    This view collects various statistics such as user counts, channel counts, 
    RSS source and entry counts, and details about pending and processed tasks. 

    Args:
        request (HttpRequest): The incoming HTTP request.

    Returns:
        HttpResponse: Rendered HTML page with the summary statistics.
    """
    # Collecting summary statistics for guilds
    user_count_dict = {}

    # Iterate through each guild to gather user and bot counts
    for guild in DiscordGuild.objects.all():
        members = DiscordGuildMember.objects.filter(guild_id=guild)

        # Count users and bots in this guild
        users_count = members.filter(user_id__bot=False).count()
        bot_count = members.filter(user_id__bot=True).count()
        total_count = users_count + bot_count

        # Store the counts as a tuple in the dictionary, keyed by the guild's name
        user_count_dict[guild.name] = (users_count, bot_count, total_count)

    # Last server sync
    last_sync = BotTask.objects.filter(name="sync_server", processed__isnull=False).order_by('-processed').first()
    if last_sync:
        last_sync = last_sync.processed

    # Fetching all Discord Channels and counts
    channels = DiscordChannel.objects.all()
    channel_count = channels.count()

    # Counting RSS sources and entries
    rss_source_count = RSSSource.objects.count()
    rss_entry_count = RSSEntry.objects.count()

    # Counting processed and pending bot tasks
    pending_tasks_count = BotTask.objects.filter(processed__isnull=True).count()
    processed_tasks_count = BotTask.objects.filter(processed__isnull=False).count()

    # Get the date of the last processed task
    last_processed_task = BotTask.objects.filter(processed__isnull=False).order_by('-processed').first()
    last_processed_task_date = last_processed_task.processed if last_processed_task else "No processed tasks"

    # Context to be passed to the template
    context = {
        'user_count': user_count_dict,
        'last_sync': last_sync,
        'channels': channels,
        'channel_count': channel_count,
        'rss_source_count': rss_source_count,
        'rss_entry_count': rss_entry_count,
        'pending_tasks_count': pending_tasks_count,
        'processed_tasks_count': processed_tasks_count,
        'last_processed_task_date': last_processed_task_date,
    }

    # Render the summary template with the context
    return render(request, 'ambivis.html', context)


class inBotMasterGroup(BasePermission):
    """
    Custom permission class to check if the user belongs to the Bot Master group.

    This class is used for granting or denying access to specific API views
    based on the user's group membership.
    """

    def has_permission(self, request, view):
        """
        Check if the user is authenticated and belongs to the specified group.

        Args:
            request (HttpRequest): The incoming HTTP request.
            view (APIView): The view being accessed.

        Returns:
            bool: True if the user is authenticated and belongs to the group, otherwise False.
        """
        return request.user.is_authenticated and request.user.groups.filter(name=group_name).exists()


class Tasking(APIView):
    """
    API view for managing Discord Bot tasks.

    Provides endpoints to fetch unprocessed tasks and update their statuses.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, inBotMasterGroup]

    def get(self, request, *args, **kwargs):
        """
        Retrieve unprocessed Discord Bot tasks.

        Args:
            request (HttpRequest): The incoming HTTP request.

        Returns:
            Response: A response containing the serialized unprocessed tasks.
        """
        unprocessed_tasks = BotTask.objects.filter(processed__isnull=True)
        serializer = BotTaskSerializer(unprocessed_tasks, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        """
        Update the status of a received task based on provided data.

        Args:
            request (HttpRequest): The incoming HTTP request containing task data.

        Returns:
            Response: A response indicating success or failure of the status update.
        """
        serializer = BotTaskUpdateSerializer(data=request.data)
        if serializer.is_valid():
            task_id = serializer.validated_data['id']
            status_update = serializer.validated_data['status']

            try:
                task = BotTask.objects.get(id=task_id)
            except BotTask.DoesNotExist:
                return Response({"error": "Task not found."}, status=status.HTTP_404_NOT_FOUND)

            if status_update == "complete":
                task.processed = timezone.now()
            elif status_update == "failed":
                task.processed = None
            else:
                return Response({"error": "Invalid status."}, status=status.HTTP_400_BAD_REQUEST)

            task.save()
            return Response({"message": "Task status updated successfully."})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ServerSync(APIView):
    """
    API view for synchronizing Discord bot data.

    This includes channels, users, roles, and guilds based on provided server configuration data.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, inBotMasterGroup]

    def post(self, request, *args, **kwargs):
        """
        Synchronize server data by processing incoming configuration data.

        Args:
            request (HttpRequest): The incoming HTTP request containing server configuration data.

        Returns:
            Response: A response indicating the success of the synchronization process.
        """
        server_configs = request.data

        # Process users
        users_data = server_configs.get('DiscordUser', [])
        for user_data in users_data:
            # Use `update_or_create` for users
            DiscordUser.objects.update_or_create(
                id=user_data['id'],
                defaults={
                    'global_name': user_data.get('global_name', None),
                    'name': user_data.get('name'),
                    'bot': user_data.get('bot', False),
                }
            )

        # Process guilds
        guilds_data = server_configs.get('DiscordGuild', [])
        for guild_data in guilds_data:
            # Use `update_or_create` for guilds
            DiscordGuild.objects.update_or_create(
                id=guild_data['id'],
                defaults={
                    'name': guild_data.get('name'),
                    'icon': guild_data.get('icon'),
                    'owner': DiscordUser.objects.get(id=guild_data['owner'])
                }
            )

        # Process roles
        roles_data = server_configs.get('DiscordRole', [])
        for role_data in roles_data:
            # Use `update_or_create` for roles
            DiscordRole.objects.update_or_create(
                id=role_data['id'],
                defaults={
                    'name': role_data.get('name', ''),
                    'guild_id': DiscordGuild.objects.get(id=role_data['guild_id'])
                }
            )

        # Process guild members
        members_data = server_configs.get('DiscordGuildMember', [])
        for member_data in members_data:
            # Use `update_or_create` for guild members
            guild_member, _ = DiscordGuildMember.objects.update_or_create(
                user_id=DiscordUser.objects.get(id=member_data['user_id']),
                defaults={
                    'guild_id': DiscordGuild.objects.get(id=member_data['guild_id']),
                    'display_name': member_data.get('display_name'),
                    'pending': member_data.get('pending'),
                    'avatar': member_data.get('avatar'),
                }
            )
            # Retrieve the roles from the member_data
            role_ids = member_data.get("roles", [])
            roles = DiscordRole.objects.filter(id__in=role_ids)

            # Update the roles for the guild member
            guild_member.roles.set(roles)

        # Process channels
        channels_data = server_configs.get('DiscordChannel', [])
        for channel_data in channels_data:
            # Use `update_or_create` for channels
            DiscordChannel.objects.update_or_create(
                id=channel_data['id'],
                defaults={
                    'name': channel_data.get('name', ''),
                    'topic': channel_data.get('topic', ''),
                    'guild_id': DiscordGuild.objects.get(id=channel_data['guild_id'])
                }
            )

        return Response({"message": "Server synchronized successfully."}, status=status.HTTP_200_OK)
