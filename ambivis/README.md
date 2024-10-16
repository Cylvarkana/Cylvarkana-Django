# AMBIVIS
**Ambidextrous Vision**  
<img src="./static/images/ambivis.png" height=300>  

## 💎 About

Ambivis is a Discord bot designed for the curated monitoring of intelligence sources. It provides tools for efficient information retrieval and dissemination within Discord channels.

## ✨ Features
- **Django Commands**
  - **runbot**: Starts the bot using the command: 
    ```bash
    python3 manage.py runbot
    ```
- **Discord Commands**
  - **/lookup**: Retrieves detailed information on various entity types, including:
    - **CVE**: Use the command `/lookup cve CVE-yyyy-number` to fetch details from the BioTremor API.
    - **Username**: Use the command `/lookup username username` to check for the presence of a username across various sites using WhatsMyName.
    - **IP**: Use the command `/lookup ip IPv4-address` to retrieve details on an IP address using the Shodan API.
    - **Domain**: Use the command `/lookup domain domain-name` to fetch details about a domain using the Shodan API.
    - **Domain**: Use the command `/lookup domain domain-name` to fetch details about a domain using the Shodan API.
  - **/update**: Allows users to update the priority rating of a specific CVE using the command:
    - **CVE**: Use the command `/update cve CVE-yyyy-number priority` to change the priority level of the specified CVE.
- **Continuous Integration**
  - **RSS Integration**: Automatically delivers curated RSS feeds to designated Discord channels.

## 🛠️ Setup

### Requirements
- [Python 3.10](./requirements.txt)
- A registered Discord Bot

### Installation
Ambivis is included by default in your project. To remove it, delete `ambivis` from the *INSTALLED_APPS* section in [settings.py](../cylvarkana/settings.py).

#### Core (Global) Configuration
- **User(s)**: `ambivis_service`
- **Group(s)**: `BotMaster`
- **Credential(s)**:
  - *ambivis_bot*: This is a placeholder; log into the admin panel to update the token value for your bot.
  - *ambivis_service*: A randomly generated password for your Ambivis service account.
  - *shodan*: A Shodan.io API key.
  
#### Scheduled Task(s):
- **Fetch RSS**: Periodically pulls RSS feeds for delivery.
- **Sync Discord Configs**: Synchronizes Ambivis models with Discord data, including:
  - Guilds
  - Users
  - Members
  - Roles
  - Channels
- **Clear Bot Task Logs**: Removes old BotTasks (default: older than 7 days).

## 📜 License
![Creative Commons](https://img.shields.io/badge/Creative_Commons-4.0-white.svg?logo=creativecommons)

This project is licensed under the [Creative Commons Attribution-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-sa/4.0/).
