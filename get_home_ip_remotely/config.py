# -*- coding: utf-8 -*-
"""Config file for getting IP, email and encryption. """

# Config of getting public IP from router
# You should get them from browser after logging in router
ROUTER_IP_URL = 'http://192.168.0.1/userRpm/StatusRpm.htm'
AUTHORIZATION_HEADERS = {
    'Authorization': 'Basic YWRtaW46SklNNDgxNDg2MGppbQ=='}
IP_REGEX = r'wanPara\s+=\s+new\s+Array\(.*?"(\d+\.\d+\.\d+\.\d+)",'

# Email config
EMAIL_ADDRESS = 'your_email_address@mail.com'
SEND_FROM = EMAIL_ADDRESS
SEND_TO = [EMAIL_ADDRESS]

USER_NAME = EMAIL_ADDRESS
PASSWORD = 'your email password'

SMTP_SERVER = 'your email SMTP server address'
SMTP_PORT = 465
IMAP_SERVER = 'your email IMAP server address'
IMAP_PORT = 993

EMAIL_TAG = '[anythin-you-like] '   # to identify the specific email


# Encryption config
ENCRYPT_PASSWORD = PASSWORD # Use the same password as email
SALT = br'\x84(\x1dkY\x860\xfa\xe8\x82\xaa\xda\x1eG\xf1p'

# hosts file
HOSTS_FILE = '/etc/hosts'
