"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        lookup.py
Purpose:     Ambivis Bot command for 'lookup' functionality across various entity types.
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
import json
import asyncio
from os.path import basename
import aiohttp
import discord
from discord import app_commands

from ambivis.management.commands.runbot import client, CustomGroup
from ambivis.utils.embeds import embed_cve, domain_report, embed_ip
from core.utils.format import validate_cve, validate_ip, validate_domain

# Automatically name the command based on the file name
NAME = basename(__file__)[:-3]
DESCRIPTION = "Lookup by details on an entity by entity type [cve, username, ip, domain]"

# Create a new command group for lookups
lookup_group = CustomGroup(name=NAME, description=DESCRIPTION)

@lookup_group.command(name="cve", description="BioTremor lookup CVE by ID")
@app_commands.describe(id="CVE-yyyy-number")
async def cve_lookup(interaction: discord.Interaction, id: str):
    """
    Lookup related to CVE by its ID.
    
    Fetches details from the BioTremor API.
    Sends results back to the user.
    """
    # Validate the CVE ID format
    if not validate_cve(id):
        await interaction.response.send_message(
            "⚠️ Invalid CVE format. Use `CVE-yyyy-number`.",
            ephemeral=True
        )
        return

    # Send an initial notice to the user
    await interaction.response.send_message(
        f"🔍 Searching for CVE `{id}`... This could take a while. <@{interaction.user.id}>, we'll notify you when the results are ready.",
        ephemeral=True
    )

    # Run the lookup in the background
    try:
        results = await asyncio.to_thread(client.api_handles['biotremor'].lookup, id)

        # Check results and send an appropriate response
        if results:
            embed = embed_cve(results)
            await interaction.followup.send(
                f"**CVE Lookup Results are Ready!** <:motivated:1290688967624359987>",
                embed=embed
            )
        else:
            await interaction.followup.send(
                f"No results found for CVE **{id.upper()}**. <:sad:1290688982681784371>",
                ephemeral=True
            )

    except Exception as e:
        # Handle any lookup or processing errors
        client.logger.error(f"{interaction.user} encountered an error while using cve lookup: {e}")
        await interaction.followup.send(
            f"⚠️🔍 We encountered an issue looking up **{id.upper()}**. Please try again later.",
            ephemeral=True
        )

# Constants for WhatsMyName lookup
WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
WMN_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9"
}

async def check_site(session, site, username):
    """
    Check a specific site for the presence of the username.

    Args:
        session (aiohttp.ClientSession): The session to use for the request.
        site (dict): Site configuration containing URL and expected response.
        username (str): The username to check.

    Returns:
        tuple or None: Site name and URL if the username is found, None otherwise.
    """
    try:
        async with session.get(site["uri_check"].format(account=username), headers=WMN_HEADERS) as response:
            text = await response.text()
            if response.status == site["e_code"] and site["e_string"] in text:
                print(f"Username '{username}' found on site {site['name']}")  # Logging
                return site["name"], site["uri_check"].format(account=username)
    except Exception as e:
        print(f"Error checking {site['name']}: {e}")
    return None

async def check_username_existence(username, data):
    """
    Check multiple sites for the existence of a username.

    Args:
        username (str): The username to check.
        data (dict): Data containing site configurations.

    Returns:
        list: Sites where the username was found.
    """
    found_sites = []
    async with aiohttp.ClientSession() as session:
        tasks = [check_site(session, site, username) for site in data["sites"]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        found_sites.extend([res for res in results if res is not None])
    print(f"Found username '{username}' on {len(found_sites)} sites.")  
    return found_sites

@lookup_group.command(name="username", description="WhatsMyName username lookup")
@app_commands.describe(username="username")
async def username_lookup(interaction: discord.Interaction, username: str):
    """
    Lookup for a username using the WhatsMyName service.
    
    Validates the username, fetches data, and sends results to the user.
    """
    await interaction.response.send_message(
        f"🔍 Checking for username `{username}`... This could take a while. <@{interaction.user.id}>, we'll let you know when your results are ready.",
        ephemeral=True
    )

    data = None
    async with aiohttp.ClientSession() as session:
        try:
            response = await session.get(WMN_URL, headers=WMN_HEADERS)

            if response.content_type != 'application/json':
                print(f"Unexpected content type: {response.content_type}")
                data_content = await response.text()
                data = json.loads(data_content)
            else:
                data = await response.json()

        except Exception as e:
            print(f"Error fetching WMN data: {e}")
            await interaction.followup.send("Failed to fetch data from WMN.")
            return

    if data:
        found_sites = await check_username_existence(username, data)
        if found_sites:
            embed = discord.Embed(title=f"Websites found for '{username}'", color=0x3498db)
            for site, url in found_sites:
                embed.add_field(name=site, value=url, inline=False)
            embed.set_footer(text="Powered by WhatsMyName | ❤️ Webbreacher, OSINT Tactical")
            await interaction.followup.send(
                f"**Username Lookup Results are Ready!** <:motivated:1290688967624359987>",
                embed=embed
            )
        else:
            await interaction.followup.send(f"No websites found for username '{username}'. <:sad:1290688982681784371>")
    else:
        client.logger.error(f"{interaction.user} encountered an error while using username lookup.")
        await interaction.followup.send("⚠️🔍 Nothing was found or an error occurred.")

@lookup_group.command(name="ip", description="Shodan lookup by IP address")
@app_commands.describe(ip="IPv4 address to look up")
async def ip_lookup(interaction: discord.Interaction, ip: str):
    """
    Lookup for IP address details using the Shodan API.
    
    Validates the IP address format and fetches results, sending them back to the user.
    """
    # Validate the IP address format
    if not validate_ip(ip):
        await interaction.response.send_message(
            "⚠️ Invalid IP address format. Please enter a valid IPv4 address.",
            ephemeral=True
        )
        return

    # Send an initial notice to the user
    await interaction.response.send_message(
        f"🔍 Searching for details on IP `{ip}`... This might take a few moments. <@{interaction.user.id}>, we'll notify you when the results are ready.",
        ephemeral=True
    )
    
    # Run the lookup in the background
    try:
        # Show remaining credits (even though IP endpoint is free)
        shodan_info = client.api_handles['shodan'].info()
        credits = shodan_info.get('query_credits', '?')
        
        results = await asyncio.to_thread(client.api_handles['shodan'].host, ip)

        # Check results and send an appropriate response
        if results:
            embed = embed_ip(results)
            message = f"**IP Lookup Results are Ready!** <:motivated:1290688967624359987>\nRemaining Credits `{credits}`"
            await interaction.followup.send(message, embed=embed)
        else:
            await interaction.followup.send(
                f"No results found for IP **{ip}**. <:sad:1290688982681784371>\nRemaining Credits `{credits}`",
                ephemeral=True
            )

    except Exception as e:
        # Handle any lookup or processing errors
        client.logger.error(f"{interaction.user} encountered an error while using IP lookup: {e}")
        await interaction.followup.send(
            f"⚠️🔍 We encountered an issue looking up **{ip}**. Please try again later.",
            ephemeral=True
        )

@lookup_group.command(name="domain", description="Shodan lookup by domain")
@app_commands.describe(domain="Domain name to look up", output_format="Output format (md or html)")
@app_commands.choices(output_format=[
    app_commands.Choice(name="Markdown", value="md"),
    app_commands.Choice(name="HTML", value="html")
])
async def domain_lookup(interaction: discord.Interaction, domain: str, output_format: str = 'md'):
    """
    Lookup for domain name details using the Shodan API.
    
    Validates the domain format, fetches results, and sends them back to the user.
    
    Args:
        interaction (discord.Interaction): Discord interaction object.
        domain (str): The domain name to look up.
        format (str): The format for the output ('md' for Markdown, 'html' for HTML).
    """
    # Validate the domain format
    if not validate_domain(domain):
        await interaction.response.send_message(
            "⚠️ Invalid domain format. Please enter a valid domain name.",
            ephemeral=True
        )
        return

    # Send an initial notice to the user
    await interaction.response.send_message(
        f"🔍 Searching for details on domain `{domain}`... This might take a few moments. <@{interaction.user.id}>, we'll notify you when the results are ready.",
        ephemeral=True
    )

    # Run the lookup in the background
    try:
        # Show remaining credits (even though domain endpoint is free)
        shodan_info = client.api_handles['shodan'].info()
        credits = shodan_info.get('query_credits', '?')

        # Perform the Shodan domain lookup
        results = await asyncio.to_thread(client.api_handles['shodan'].dns.domain_info, domain)

        # Check results and send an appropriate response
        if results:
            report_file = domain_report(results, output_format=output_format)
            message = f"""\
**Domain Lookup Results are Ready!** <:motivated:1290688967624359987>
>   **{domain}**
>   Remaining Credits `{credits}`
>   Powered by *Shodan*
"""
            await interaction.followup.send(message, file=report_file)
        else:
            await interaction.followup.send(
                f"No results found for domain **{domain}**. <:sad:1290688982681784371>\nRemaining Credits `{credits}`",
                ephemeral=True
            )

    except Exception as e:
        # Handle any lookup or processing errors
        client.logger.error(f"{interaction.user} encountered an error while using domain lookup: {e}")
        await interaction.followup.send(
            f"⚠️🔍 We encountered an issue looking up **{domain}**. Please try again later.",
            ephemeral=True
        )

# Register the command group to the client
client.add_group_command(lookup_group)
