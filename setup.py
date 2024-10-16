"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
Name:        setup.py
Purpose:     Setup and initialize the cylvarkana environment
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/19/2024
Copyright:   (c) Kodama Chameleon 2024
Licence:     CC BY 4.0
"""
import os
import time
import shutil
import string
import random
import subprocess
import sys
import base64

# List of apps with their own requirements
APPS = ['ambivis', 'biotremor', 'core']

def generate_random_password(length: int = 50) -> str:
    """
    Generate a random secure string of the given length.
    This is used for secrets like passwords or encryption keys.
    
    Args:
        length (int): Length of the generated string. Default is 50.
    
    Returns:
        str: A randomly generated secure string.
    """
    characters = string.ascii_letters + string.digits + '!@$%^&*'
    return ''.join(random.choice(characters) for _ in range(length))

def install_app_requirements(apps: list):
    """
    Install Python package dependencies for each app by reading the
    requirements.txt file from each app's directory.
    
    Args:
        apps (list): List of app names to install dependencies for.
    """
    for app in apps:
        requirements_file = os.path.join(app, 'requirements.txt')
        if os.path.exists(requirements_file):
            print(f"Installing requirements for {app}...")
            try:
                subprocess.check_call([
                    sys.executable,
                    '-m', 'pip', 'install', '-r',
                    requirements_file
                ])
                print(f"Successfully installed requirements for {app}.")
            except subprocess.CalledProcessError as e:
                print(f"Failed to install requirements for {app}: {e}")
                sys.exit(1)
        else:
            print(f"No requirements.txt found for {app}. Skipping.")

def setup_environment_file():
    """
    Create a .env file from .env_example if it doesn't already exist.
    This file contains environment variables used by Django and other services.
    """
    if os.path.exists('.env'):
        print(".env file already exists. Skipping copy.")
    else:
        shutil.copy('.env_example', '.env')
        print("Copied .env_example to .env")

def populate_env_with_secrets():
    """
    Populate the .env file with secure, randomly generated values for sensitive
    environment variables like SECRET_KEY and DATABASE_PASSWORD.
    
    It replaces placeholders in the .env file with actual secure values.
    """
    env_file = '.env'
    if os.path.exists(env_file):
        with open(env_file, 'r', encoding="utf-8") as file:
            content = file.read()

        # Generate secure values for the environment variables
        secret_key = generate_random_password(50)
        encryption_key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        database_password = generate_random_password(50)

        # Replace placeholders with secure values
        content = content.replace('SECRET_KEY=<change_me>', f'SECRET_KEY={secret_key}')
        content = content.replace('FIELD_ENCRYPTION_KEY=<change_me>', f'FIELD_ENCRYPTION_KEY={encryption_key}')
        content = content.replace('DATABASE_PASSWORD=<change_me>', f'DATABASE_PASSWORD={database_password}')

        with open(env_file, 'w', encoding="utf-8") as file:
            file.write(content)

        print("Updated .env with secure SECRET_KEY and DATABASE_PASSWORD")
    else:
        print(f"{env_file} does not exist. Ensure you have copied .env_example to .env first.")

def start_docker_containers():
    """
    Start the Docker containers using docker-compose.
    This will bring up services like the PostgreSQL database and Redis.
    """
    try:
        subprocess.check_call(['docker-compose', 'up', '-d'])
        print("Spinning up containers.")
        time.sleep(5)  # Wait for containers to initialize
        print("Docker containers are up and running.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to launch docker-compose: {e}")
        sys.exit(1)

def apply_migrations_with_retry():
    """
    Apply Django database migrations. If the initial attempt fails, retry with --fake-initial option.
    This ensures the database schema is properly set up and matches the models.
    """
    try:

        # Migrate core first to ensure core models are in place
        print("Applying core migrations...")
        subprocess.check_call(['python3', 'manage.py', 'makemigrations', 'core'])
        subprocess.check_call(['python3', 'manage.py', 'migrate', 'core'])
        time.sleep(3)

        # Apply other migrations
        subprocess.check_call(['python3', 'manage.py', 'makemigrations'])
        time.sleep(3)
        subprocess.check_call(['python3', 'manage.py', 'migrate'])
        time.sleep(3)
    except subprocess.CalledProcessError as e:
        print("Migration failed, retrying with --fake-initial.")
        time.sleep(3)
        try:
            subprocess.check_call(['python3', 'manage.py', 'makemigrations'])
            time.sleep(3)
            subprocess.check_call(['python3', 'manage.py', 'migrate', '--fake-initial'])
        except subprocess.CalledProcessError:
            print(f"ERROR: Failed to apply migrations: {e}")

def create_django_superuser():
    """
    Create a new Django superuser interactively via the command line.
    This user will have admin access to the Django admin interface.
    """
    try:
        print("Creating Django default superuser")
        subprocess.check_call(['python3', 'manage.py', 'createsuperuser'])
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to create superuser: {e}")

if __name__ == '__main__':

    # Set the DJANGO_SETTINGS_MODULE environment variable for Django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cylvarkana.settings')

    # Install requirements for each app
    install_app_requirements(APPS)

    # Set up and populate environment variables
    setup_environment_file()
    populate_env_with_secrets()

    # Start services and run database migrations
    start_docker_containers()
    apply_migrations_with_retry()

    # Create a superuser for Django admin
    create_django_superuser()
