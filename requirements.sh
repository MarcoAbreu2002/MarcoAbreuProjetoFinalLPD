#!/bin/bash

# Update package lists
sudo apt update

# Upgrade Python 3
sudo apt upgrade python3

# Install gnome-terminal
sudo apt install gnome-terminal

# Install Python dependencies using pip
pip install pycryptodome scapy paramiko reportlab
