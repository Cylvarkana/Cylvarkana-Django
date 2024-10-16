"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        runbot.py
Purpose:     Django Discord Bot handling
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/23/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from os.path import join, dirname, isfile, basename
from importlib import import_module
import glob
import asyncio
import discord
from discord import app_commands
from shodan import Shodan

from django.core.management import BaseCommand
from django.core.exceptions import ObjectDoesNotExist

from core.models import Credential
from ambivis.apps import logger
from ambivis.utils.api import Ambivis
from django.conf import settings

def initialize_apis(username: str=None, password: str=None) -> Ambivis:
    """
    Initialize access to the Ambivis API
    """

    # Default call to Ambivis Credential model
    if not username or not password:
        try:
            bot_creds = Credential.objects.get(
                platform='ambivis',
                id='ambivis_service',
                cred_type='password'
            )
            username = bot_creds.id
            password = bot_creds.value
        except Credential.DoesNotExist:
            logger.error("Ambivis bot credentials not found in Credential model.")
            return None
        except Exception as e:
            logger.error(f"Error fetching credentials from Credential model: {e}")
            return None

    # create ambivis api handle
    api_handles = {}
    try:
        api_handles['ambivis'] = Ambivis(username=username, password=password)
        logger.info(f"Successfully authenticated to Ambivis API.")
    except Exception as e:
        raise ConnectionError(f"Failed to connect to Ambivis API: {e}")

    # Create shodan api handle if shodan key
    shodan_key = Credential.objects.filter(id="shodan_service", platform="shodan", cred_type="key").first().value
    if shodan_key:
        api_handles['shodan'] = Shodan(shodan_key)
        logger.info("Shodan API key found. Initialized Shodan API.")

    # create biotremor api handle (if installed)
    if "biotremor" in settings.INSTALLED_APPS:
        try:
            from biotremor.utils.api import BioTremor
            api_handles['biotremor'] = BioTremor(username=username, password=password)
            logger.info("Successfully authenticated to BioTremor API.")
        except Exception as e:
            logger.error(f"Failed to connect to BioTremor API: {e}")
            api_handles['biotremor'] =  None

    return api_handles

class CustomGroup(app_commands.Group):
    """
    Empty shell for creating custom group commands
    """
    pass

class BotHandler(discord.Client):
    """
    Define custom bot handling
    """

    def __init__(self, api_handles: dict) -> None:
        """
        - Utilize tree decorator
        - Set activity
        - Define message length limit
        """

        # Enable specific intents
        intents = discord.Intents.default()
        intents.members = True

        # Initialize the client with custom intents
        super().__init__(intents=intents)

        self.tree = discord.app_commands.CommandTree(self)
        self.activity = discord.Activity(type=discord.ActivityType.watching, name="1's and 0's 👾🔍")
        self.discord_message_limit = 2000
        self.logger = logger
        self.api_handles = api_handles

    def add_group_command(self, group_command):
        """
        Custom method for adding grouped commands
        """
        self.tree.add_command(group_command)

    async def on_ready(self):
        """
        Startup tasks for the Discord Bot
        """
        # Log status
        self.logger.info(f'We have logged in as {self.user}')

        # Sync commands
        try:
            await self.tree.sync()
            self.logger.info("Commands synced successfully.")
        except Exception as e:
            self.logger.error(f"Failed to sync commands: {e}")
    
        # Sync server configs
        try:
            from .bot.system import sync_server
            await sync_server()
            self.logger.info("Server configs synced successfully.")
        except Exception as e:
            self.logger.error(f"Failed to sync server configs: {e}")

        # Start listining for tasking (dependent on successful API connection)
        if self.api_handles['ambivis']:
            self.loop.create_task(self.poll_for_tasks())

    async def poll_for_tasks(self, periodicity: int=30):
        """
        Check for incomplete tasks
        """
        while True:
            await asyncio.sleep(periodicity)

            # Fetch unprocessed tasks
            try:
                tasking = self.api_handles['ambivis'].get_tasks()
                self.logger.debug(f"Pulled {len(tasking)} new tasks to process")

                for task in tasking:

                    try:
                        # Execute tasking
                        await self.compile_task(task)

                        # Acknowledge completion
                        self.api_handles['ambivis'].post_task_status(task['id'], "complete")

                    except Exception as e:
                        client.logger.error(e)
                        self.api_handles['ambivis'].post_task_status(task['id'], "failed")    

            except Exception as e:
                self.logger.error(f"Error fetching or processing tasks: {e}")

    async def compile_task(self, task: dict):
        """
        Executes a task by dynamically calling the function specified in kwargs.
        The function arguments are expected in the 'f_args' field of kwargs.
        """
        # Lazy import to avoid circular imports
        from .bot import system

        # Get the function name from kwargs
        function_name = task.get('name', None)
        function_args = task.get('args', None)
        function_kwargs = task.get('kwargs', None)

        if function_name:
            # Get the function reference from the current class (self)
            func = getattr(system, function_name, None)
            if func:
                await self.execute_task(func, function_args, function_kwargs)
            else:
                logger.error(f"Function '{function_name}' not found.")
        else:
            logger.error("No function name specified in kwargs.")

    async def execute_task(self, func, args: list, kwargs: dict):
        """
        Execute function based on provided args and kwargs
        """
        try:
            # Check if the function is asynchronous
            if asyncio.iscoroutinefunction(func):
                if args and kwargs:
                    await func(*args, **kwargs)
                elif args and not kwargs:
                    await func(*args)
                elif not args and kwargs:
                    await func(**kwargs)
                else:
                    await func()

            # Synchronous operations handling
            else:
                if args and kwargs:
                    func(*args, **kwargs)
                elif args and not kwargs:
                    func(*args)
                elif not args and kwargs:
                    func(**kwargs)
                else:
                    func()

        except Exception as e:
            # Log any errors that occur during the function execution
            raise SyntaxError(f"Error executing function '{func}' with args {args} and kwargs {kwargs}: {e}")

    async def send_split_messages(
            self,
            interaction,
            message: str,
            embed=None,
            require_response=True
        ):
        """
        Sends a message that may be too long for Discord's message limit by splitting it into chunks.

        :param interaction: The Discord interaction object.
        :param message: The message content to be split and sent.
        :param embed: A list of discord.Embed objects to be included with the message (optional).
        :param require_response: Whether a response is required (defaults to True).
        """
        if not message.strip():
            self.logger.error("Attempted to send an empty message.")
            return

        lines = message.split("\n")
        chunks = []
        current_chunk = ""

        for line in lines:
            if len(current_chunk) + len(line) + 1 > self.discord_message_limit:
                chunks.append(current_chunk)
                current_chunk = line + "\n"
            else:
                current_chunk += line + "\n"

        if current_chunk:
            chunks.append(current_chunk)

        if not chunks:
            self.logger.error("No chunks generated from the message.")
            return

        if require_response and not interaction.response.is_done():
            await interaction.response.defer(ephemeral=False)

        for chunk in chunks:
            try:
                await interaction.followup.send(content=chunk, embed=embed, ephemeral=False)
            except Exception as e:
                self.logger.error(f"Failed to send a message chunk to the channel. Error: {e}")

    async def handle_errors(self, interaction, error_message=None):
        """
        Dedicate error handling for Discord Bot
        """
        user_friendly_message = "An error occurred while processing your request. Please try again later."
        self.logger.error(f"Error: {error_message if error_message else 'Unknown error'}")
        if error_message:
            user_friendly_message += f"\n\nDetails: {error_message}"

        if not interaction.response.is_done():
            await interaction.response.send_message(user_friendly_message, ephemeral=True)
        else:
            await interaction.followup.send(user_friendly_message, ephemeral=True)

    async def fetch_channels(self):
        """
        Pull list of all channel data for which Ambivis is a part
        """
        bot_channels = []

        # Fetch and process channels
        for guild in self.guilds:
            for channel in guild.channels:
                bot_channels.append({
                    'id': channel.id,
                    'name': channel.name,
                    'topic': getattr(channel, 'topic', ''),
                    'guild_id': guild.id
                })

        return bot_channels

# Initialize client
client = BotHandler(api_handles=initialize_apis())

class Command(BaseCommand):
    """
    Register the runbot command to Django manage.py
    """
    help = 'runs the discordBot bot'

    def handle(self, *args, **options):
        logger.info("Running Ambivis Bot")

        # Retrieve the token from the Cred model
        try:
            bot_token = Credential.objects.get(platform='discord', id='ambivis_discord', cred_type='token')

        except ObjectDoesNotExist:
            self.stderr.write("Discord token not found in Credential model.")
            return

        logger.info("Importing modules dynamically\nCommands Loaded:")
        modules = glob.glob(join(dirname(__file__), "bot", "*.py"))
        for f in modules:
            if isfile(f) and not f.endswith("__init__.py"):
                module = import_module(".bot." + basename(f)[:-3], "ambivis.management.commands")
                logger.info(f"{basename(f)[:-3]} [OK]")
        # print_commands()
        logger.info("\nRuntime!")

        client.run(bot_token.value)
