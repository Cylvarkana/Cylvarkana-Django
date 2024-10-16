"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        system.py
Purpose:     Callable functions from the ambivis BotTasks model
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from os.path import basename
from datetime import datetime

from ambivis.management.commands.runbot import client
from ambivis.utils.embeds import embed_rss


# Auto name the command
NAME = basename(__file__)[:-3]
DESCRIPTION = "System tasks callable via BotTasks models in the Ambivis ORM"


async def send_rss(
    source: str,
    title: str,
    link: str,
    description: str,
    channel_id: int,
    author: str=None,
    enclosure: str=None,
    published_date: datetime=None,
    color: str=None,
):
    """
    Send RSS messages to a Discord channel.
    
    :param source: Source of the RSS feed.
    :param title: Title of the RSS item.
    :param description: Description of the RSS item.
    :param link: Unique identifier or URL for the RSS item.
    :param enclosure: Image url to display for embed.
    :param published_date: Publication date of the RSS item.
    :param channel_id: Which channel to send to.
    """

    # Create the embed using the provided RSS data
    embed = embed_rss(
        title=title,
        description=description,
        link=link,
        enclosure=enclosure,
        published_date=published_date,
        author=author,
        color=color
    )

    # Send message
    channel = client.get_channel(int(channel_id))
    if channel:
        await channel.send(f"**{source} Feed**",embed=embed)
    else:
        client.logger.error(f"Channel with ID {channel_id} not found.")

async def sync_server():
    """
    Send Ambivis server data to the Django backend.
    """
    # Fetch channel data using the BotHandler client instance
    bot_channels = await client.fetch_channels()

    # Compile System Info
    guilds = client.guilds
    discord_users = []
    guild_members = []
    guild_list = []
    role_list = []
    for guild in guilds:

        # Append guild
        guild_dict = {
            "id": str(guild.id),
            "name": guild.name,
            "icon": guild.icon.url,
            "owner": guild.owner.id
        }
        guild_list.append(guild_dict)

        async for member in guild.fetch_members():

            # Append discord user
            discord_user = {
                "id": str(member.id),
                "name": member.name,
                "display_name": member.display_name,
                "bot": member.bot,
            }
            discord_users.append(discord_user)

            # Append membership info
            guild_member = {
                "user_id": str(member.id),
                "guild_id": str(guild.id),
                "display_name": member.display_name,
                "pending": member.pending,
                "roles": [role.id for role in member.roles],
                "avatar": member.avatar.url if member.avatar else None,
            }
            guild_members.append(guild_member)

        for role in guild.roles:
            # Append roles
            discord_role = {
                "id": role.id,
                "name": role.name,
                "guild_id": str(guild.id),
            }
            role_list.append(discord_role)


    # Prepare the data to send to the Ambivis API
    server_configs = {
        "DiscordChannel": bot_channels,
        "DiscordUser": discord_users,
        "DiscordGuild": guild_list,
        "DiscordGuildMember": guild_members,
        "DiscordRole": role_list
    }

    # Send the data to the Ambivis API
    try:
        client.api_handles['ambivis'].sync_server_data(server_configs)

        # Removed direct response check here since sync_server_data raises an exception on failure
        client.logger.info("Server data synchronized successfully.")

    except Exception as e:
        client.logger.error(f"Error while sending server data to Ambivis: {e}")
