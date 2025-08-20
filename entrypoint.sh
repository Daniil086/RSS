#!/bin/sh

# Go to the right directory
cd /opt/opencti-rss-connector

# Ensure log file exists and is writable
touch connector.log
chmod 666 connector.log

# Launch the connector
python3 main.py
