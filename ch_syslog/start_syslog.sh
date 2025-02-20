#!/bin/bash

# Set the project directory
PROJECT_DIR="/home/net/django_project/ch_syslog"
VENV_DIR="/home/net/django_project/venv"

# Export necessary environment variables
export PYTHONPATH=$PROJECT_DIR
export VIRTUAL_ENV=$VENV_DIR
export PATH=$VENV_DIR/bin:$PATH

# Change to project directory
cd $PROJECT_DIR

# Start the syslog receiver
exec sudo -E $VENV_DIR/bin/python3 manage.py syslog_receiver "$@" 