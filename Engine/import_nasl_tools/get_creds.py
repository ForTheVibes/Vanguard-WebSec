import configparser
import sys
import os

# Get the current file's directory
current_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(current_dir, '..', 'engine.conf')

# Load the configuration file
config = configparser.ConfigParser()
config.read(file_path)  # Replace 'config.ini' with the actual file path

def get_ssh_creds():
    # Access the ssh credentials
    username_ssh = config.get('ssh-port22', 'username_ssh')
    password_ssh = config.get('ssh-port22', 'password_ssh')
    return username_ssh, password_ssh

def get_dvwa_creds():
    # Access the DVWA credentials
    username_dvwa = config.get('http_dvwa-port80', 'username_dvwa')
    password_dvwa = config.get('http_dvwa-port80', 'password_dvwa')
    return username_dvwa, password_dvwa
