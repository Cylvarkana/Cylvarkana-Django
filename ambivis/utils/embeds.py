"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        embeds.py
Purpose:     Format embeds for Discord bot delivery
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     10/07/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from datetime import datetime
import io
import discord

def embed_cve(cve_data: dict) -> discord.Embed:
    """
    Convert CVE API response to a discord Embed object.
    
    :param cve_data: Dictionary representing CVE data from API response
    :return: discord.Embed object
    """
    # Parse response fields
    cve_id = cve_data.get("id")
    vuln_name = cve_data.get("cisa_vulnerability_name", None)
    description = cve_data.get("description", None)
    published_date = cve_data.get("published", None)

    # Create Embed message
    embed = discord.Embed(
        title=cve_id,
        color=0xff000d,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    )

    # Generate summary
    summary = ""
    if vuln_name:
        summary += f"**{vuln_name}**\n"
    if description:
        # Limit description length
        if len(description) > 500:
            description = f"{description[:500].strip()}..."
        summary += description
    if summary:
        embed.description = summary

    # Embed fields
    fields = [
        "priority",
        "rating_method",
        "cisa_exploit_add",
        "EPSS.score",
        "EPSS.percentile",
        "weakness",
        "reference"
    ]
    for field in fields:
        if field in cve_data and cve_data[field]:
            # Replace dots and underscores with spaces
            field_name = field.replace(".", " ").replace("_", " ")

            # Capitalize first letter of each word unless the word is in all caps
            field_name = " ".join([
                word if word.isupper() else word.capitalize()
                for word in field_name.split()
            ])

            # Format field name as bold and add the field to the embed
            field_name = f"**{field_name}**"

            # Format field values
            if len(cve_data[field]) == 1:
                value = str(cve_data[field][0])
            else:
                value = ""
                for row in cve_data[field]:
                    value += f"- {str(row)}\n"
                value = value[:-1]

            embed.add_field(name=field_name, value = value, inline=False)

    if published_date:
        embed.timestamp = datetime.fromisoformat(published_date)

    # Set footer and return embed
    embed.set_footer(text='Powered by BioTremor')
    return embed

def embed_ip(ip_data: dict) -> discord.Embed:
    """
    Convert Shodan API response to a discord Embed object for IP information.
    
    :param ip_data: Dictionary representing IP data from Shodan API response
    :return: discord.Embed object
    """
    # Parse response fields
    ip_address = ip_data.get("ip_str")
    last_update = ip_data.get("last_update", None)

    # Create Embed message
    embed = discord.Embed(
        title=ip_address,
        color=0x00ff00,
        url=f"https://www.shodan.io/host/{ip_address}"
    )

    # Fields to display in the embed
    fields = {
        "ASN": ip_data.get("asn"),
        "Country": ip_data.get("country_name"),
        "ISP": ip_data.get("isp"),
        "Organization": ip_data.get("org"),
        "Hostnames": ", ".join(ip_data.get("hostnames", [])),
        "Domains": ", ".join(ip_data.get("domains", [])),
        "Open Ports": ", ".join(map(str, ip_data.get("ports", []))),
        "Operating System": ip_data.get("os"),
        "Location": f"Lat: {ip_data.get('latitude')}, Lon: {ip_data.get('longitude')}"
            if ip_data.get('latitude') and ip_data.get('longitude') else None
    }

    # Add fields to the embed if they exist and are not None/empty
    for field_name, field_value in fields.items():
        if field_value:  # Check if value is not None or empty
            embed.add_field(name=field_name, value=field_value, inline=False)

    # Add the timestamp from last update if available
    if last_update:
        embed.timestamp = datetime.fromisoformat(last_update)

    # Set footer and return embed
    embed.set_footer(text='Powered by Shodan')
    return embed


def domain_report(domain_data: dict, output_format: str = 'md') -> discord.File:
    """
    Convert domain lookup results into a file in the specified format (Markdown or HTML).

    :param domain_data: Dictionary representing domain data from Shodan API response
    :param format: The format to output the report ('md' for Markdown, 'html' for HTML)
    :return: discord.File object containing the report
    """
    domain_name = domain_data.get("domain")
    subdomains = domain_data.get("subdomains", [])
    dns_records = domain_data.get("data", [])

    if output_format == 'md':
        # Initialize Markdown Report
        report_content = f"# {domain_name.upper()} REPORT\n"

        # Add Subdomains to Report
        report_content += "## Subdomains\n"
        if subdomains:
            for subdomain in subdomains:
                report_content += f"- {subdomain}\n"
        else:
            report_content += "- None\n"

        # Add DNS Records as Markdown Table
        report_content += "## DNS Records\n"
        report_content += "| Subdomain | Record Type | Ports | Value | Last Seen |\n"
        report_content += "|-----------|-------------|-------|-------|-----------|\n"

        for record in dns_records:
            subdomain = record.get('subdomain', '')
            record_type = record.get('type', '')
            ports = ', '.join(map(str, record.get('ports', []))) if record.get('ports') else ''
            value = record.get('value', '')
            last_seen_subdomain = record.get('last_seen', '')

            # Add a row for each DNS record
            report_content += f"| {subdomain} | {record_type} | {ports} | {value} | {last_seen_subdomain} |\n"

        # Add footer
        report_content += f"\n> Powered by Shodan"

    elif output_format == 'html':
        # Initialize HTML Report
        report_content = f"<h1>{domain_name.upper()} REPORT</h1>\n"

        # Add Subdomains to Report
        report_content += "<h2>Subdomains</h2>\n<ul>\n"
        if subdomains:
            for subdomain in subdomains:
                report_content += f"  <li>{subdomain}</li>\n"
        else:
            report_content += "  <li>None</li>\n"
        report_content += "</ul>\n"

        # Add DNS Records as HTML Table
        report_content += "<h2>DNS Records</h2>\n"
        report_content += "<table border='1'>\n"
        report_content += "<tr><th>Subdomain</th><th>Record Type</th><th>Ports</th><th>Value</th><th>Last Seen</th></tr>\n"

        for record in dns_records:
            subdomain = record.get('subdomain', '')
            record_type = record.get('type', '')
            ports = ', '.join(map(str, record.get('ports', []))) if record.get('ports') else ''
            value = record.get('value', '')
            last_seen_subdomain = record.get('last_seen', '')

            # Add a row for each DNS record
            report_content += f"<tr><td>{subdomain}</td><td>{record_type}</td><td>{ports}</td><td>{value}</td><td>{last_seen_subdomain}</td></tr>\n"

        report_content += "</table>\n"
        report_content += "<p>Powered by Shodan</p>"

    else:
        raise ValueError("Invalid format specified. Use 'md' or 'html'.")

    # Build the file in memory
    file = io.StringIO(report_content)
    discord_file = discord.File(file, filename=f"{domain_name.replace('.', '-')}_report.{output_format}")

    return discord_file

def embed_rss(
        title: str,
        description: str,
        author: str,
        link: str,
        enclosure: str,
        published_date: str,
        color: str,
    ) -> discord.Embed:
    """
    Create an embed from RSS message.
    """

    # Required embed
    embed = discord.Embed(
        title=title,
        description=description,
    )

    # Optional embeds
    if author:
        embed.set_author(name=author)

    if enclosure:
        embed.set_image(url=enclosure)

    if link:
        embed.url = link

    if published_date:
        date_format = "%Y-%m-%d %H:%M:%S"
        embed.timestamp = datetime.strptime(published_date, date_format)

    if color:
        embed.color = int(color.lstrip('#'), 16)
    else:
        embed.color = 0xFFD700

    embed.set_footer(text="Powered by Ambivis")

    return embed
