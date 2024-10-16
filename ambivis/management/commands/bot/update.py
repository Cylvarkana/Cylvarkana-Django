"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        update.py
Purpose:     Ambivis Bot command 'update'. Command defaults to file name.
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
import asyncio
from os.path import basename
import discord
from discord import app_commands

from ambivis.management.commands.runbot import client, CustomGroup
from core.utils.format import validate_cve

# Auto name the command
NAME = basename(__file__)[:-3]
DESCRIPTION = "Make changes to specific entities [cve]"

# Greate new command group
lookup_group = CustomGroup(name=NAME, description=DESCRIPTION)

# Define priority levels
priority_levels = [
    (0, 'CRITICAL'),
    (1, 'HIGH'),
    (2, 'MEDIUM'),
    (3, 'LOW'),
    (4, 'UNKNOWN'),
]

# Compile priority description and choices
priority_choices = []
priority_description = ""
for value, name in priority_levels:
    priority_description += f"{value}: {name} "
    priority_choices.append(app_commands.Choice(name=name, value=value))

@lookup_group.command(name="cve", description="Update priority rating for a specific CVE")
@app_commands.describe(id="CVE-yyyy-number")
@app_commands.describe(priority=priority_description)
@app_commands.choices(priority=priority_choices)
async def cve_update(
    interaction: discord.Interaction,
    id: str,
    priority: int
):
    """
    Update CVE priority
    """
    # Validate the CVE ID format
    if not validate_cve(id):
        await interaction.response.send_message(
            "⚠️ Invalid CVE format. Use `CVE-yyyy-number`.",
            ephemeral=True
        )
        return
    # Find the corresponding priority name
    priority_name = next((name for value, name in priority_levels if value == priority), "UNKNOWN")

    # Run the lookup in the background
    try:
        results = await asyncio.to_thread(
            client.api_handles['biotremor'].rate,
            id, priority,
            f"DiscordUser.{interaction.user.id}"
        )

        # Check results and send an appropriate response
        if results:
            await interaction.response.send_message(f"🔧 <@{interaction.user.id}> updated `{id}` to priority {priority_name}. <:motivated:1290688967624359987>")
        else:
           raise
    
    except Exception as e:
        # Handle any lookup or processing errors
        await interaction.followup.send(
            f"⚠️🔧 We encountered an issue updating **{id.upper()}**. Please try again later.",
            ephemeral=True
        )

# Register command group to the client
client.add_group_command(lookup_group)
