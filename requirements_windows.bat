@echo off

rem Update package lists
sudo apt update

rem Upgrade Python 3
sudo apt upgrade python3

rem Install gnome-terminal
sudo apt install gnome-terminal

rem Install Python dependencies using pip
pip install pycryptodome scapy paramiko reportlab
