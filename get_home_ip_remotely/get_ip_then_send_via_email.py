# -*- coding: utf-8 -*-
"""
Get the dynamic public IP from router at home, encrypt it,
and send it to the remote via email automatically.
"""
import os
import re
import sys
import codecs
import base64
import smtplib
import requests
import logging

from logging import handlers

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.utils import COMMASPACE, formatdate
from email import encoders
from email.header import Header

if __name__ == '__main__':
    from config import (ROUTER_IP_URL, AUTHORIZATION_HEADERS, IP_REGEX,
            SEND_FROM, SEND_TO, USER_NAME, PASSWORD, SMTP_SERVER,
            SMTP_PORT, EMAIL_TAG, ENCRYPT_PASSWORD, SALT)
else:
    from .config import (ROUTER_IP_URL, AUTHORIZATION_HEADERS, IP_REGEX,
            SEND_FROM, SEND_TO, USER_NAME, PASSWORD, SMTP_SERVER,
            SMTP_PORT, EMAIL_TAG, ENCRYPT_PASSWORD, SALT)


# config logger
LOGNAME = os.path.splitext(
        os.path.basename(__file__))[0] if __name__ == '__main__' else __name__
LOGGER = logging.getLogger(LOGNAME)
LOGGER.setLevel(logging.DEBUG)
FORMATTER = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

LOGFILE = os.path.splitext(os.path.abspath(__file__))[0] + '.log'
HANDLERFILE = handlers.RotatingFileHandler(LOGFILE)
HANDLERFILE.setFormatter(FORMATTER)
LOGGER.addHandler(HANDLERFILE)

HANDLERSTDOUT = logging.StreamHandler(sys.stdout)
HANDLERSTDOUT.setFormatter(FORMATTER)
LOGGER.addHandler(HANDLERSTDOUT)


def get_ip_from_router(router_ip_url, authorization_headers, ip_regex,
        logger=LOGGER):
    """Get the dynamic public IP from router at home.

    You should log in the router using browser, and study it to
    get the three arguments. 

    :param str router_ip_url: URL of page that displays public IP realtime.
    :param dict authorization_headers: request HTTP headers for authorization.
    :param str ip_regex: regex string for searching public IP.

    example::

        router_ip_url = 'http://192.168.0.1/userRpm/StatusRpm.htm'
        authorization_headers = {
            'Authorization': 'Basic YWRtaW46SklNNDgxNDg2MGppbQ=='}
        ip_regex = r'wanPara\s+=\s+new\s+Array\(.*?"(\d+\.\d+\.\d+\.\d+)",'

    """

    assert router_ip_url, (
            'Please input the URL of page that displays public ip realtime')
    assert authorization_headers, (
            'Please input the authorization header for HTTP request')
    assert ip_regex, (
            'Please input regular expression for find public IP')

    r = requests.get(router_ip_url, headers=authorization_headers)
    if r.status_code != 200:
        if logger:
            logger.critical('Cannot access router, url: %s' % router_ip_url)
        sys.exit(1)

    m = re.search(ip_regex, r.text, re.DOTALL)
    if m:
        ip = m.groups()[0]
        if logger:
            logger.info('The new public IP: %s' % ip)
    else:
        if logger:
            logger.critical('Cannot get the public IP.')
        sys.exit(1)

    return ip

def send_mail(send_from, send_to, subject, user_name, password, text='',
        html='', img='', files=[], cc_to=[], server="localhost", port=465,
        logger=LOGGER):
    """Send email with plain text or HTML text.

    :param list send_from: sender email address.
    :param list send_to: receiver emails address list.
    :param str subject: title of email.
    :param str user_name: user name of email account.
    :param str password: password of email account.
    :param str text: plain text to send.
    :param str html: HTML text to send.
    :param str img: image file path to send.
    :param list files: files list as attachement.
    :param list cc_to: cc emails address list.
    :param str server: email SMTP server IP or domain.
    :param int port: email SMTP server port.
    """
    assert type(send_to)==list
    assert type(cc_to)==list
    assert type(files)==list

    # msg = MIMEMultipart('alternative')
    msg = MIMEMultipart('related')
    # msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['cc'] = COMMASPACE.join(cc_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    # Encapsulate the plain and HTML versions of the message body in an
    # 'alternative' part, so message agents can decide which they want to display.
    # msgAlternative = MIMEMultipart('alternative')
    # msg.attach(msgAlternative)

    if text != '':
        msg.attach(MIMEText(text, 'plain', 'utf-8'))
    if html != '':
        msg.attach(MIMEText(html, 'html', 'utf-8'))

    # imgf = r'/img/path/'
    if img != '':
        fp = open(img, 'rb')
        msgImage = MIMEImage(fp.read())
        fp.close()
        msgImage.add_header('Content-ID', '<image1>')
        msgImage.add_header('Content-Disposition', 'inline', filename=img)
        msg.attach(msgImage)

    for f in files:
        part = MIMEBase('application', "octet-stream")
        # part.set_payload( open(f, "rb").read() )
        part.set_payload(codecs.open(f, "rb").read())
        encoders.encode_base64(part)
        # print(os.path.basename(f).encode('utf8'))
        #  part.add_header('Content-Disposition', 'attachment',
        #          filename=('utf8', '', os.path.basename(f).encode('utf8')))
        part.add_header('Content-Disposition', 'attachment',
                filename=Header(os.path.basename(f), 'utf8').encode())
        #  part.add_header('Content-Disposition', 'attachment; filename=ss.xlsx')
        # print(os.path.basename(f))
        msg.attach(part)

    try:
        smtp = smtplib.SMTP_SSL(server, port)
        smtp.login(user_name, password)
        smtp.sendmail(send_from, send_to, msg.as_string())
    except Exception:
        #  print('Error happened:\n', sys.exc_info())
        if logger:
            logger.error('Error happened:\n', sys.exc_info())
        return False

    smtp.close()
    return True

def encrypt_text(text, encrypt_password, salt, logger=LOGGER):
    """Encrypt text with password and salt.

    Example::

        salt = b'\\x66(\\x1dkY\\x860\\xfa\\xe8\\x82\\x1a\\xda\\x1eG\\xf1p'

    :param str text: text to be encrypted.
    :param bytes encrypt_password: password to generate a key.
    :param bytes salt: salt key for encrypted text.
    """
    #  salt = os.urandom(16)
    #  salt = br'\x66(\x1dkY\x860\xfa\xe8\x82\x1a\xda\x1eG\xf1p'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(encrypt_password))
    f = Fernet(key)
    text = text.encode('utf-8')
    token = f.encrypt(text)
    if logger:
        logger.info('Encrypted text: {token}'.format(token=token))

    return token

def main(logger=LOGGER):
    """Get the dynamic public IP from router, encrypt it, then send it via email.

    You need config your email account and text tag to
    identify the specific email.
    """

    ip = get_ip_from_router(ROUTER_IP_URL, AUTHORIZATION_HEADERS, IP_REGEX,
            logger=logger)
    encrypted_text = encrypt_text(ip, ENCRYPT_PASSWORD.encode('utf-8'), SALT,
            logger=logger).decode('utf-8')
    subject = EMAIL_TAG + encrypted_text
    body_text = encrypted_text

    result = send_mail(SEND_FROM, SEND_TO, subject, USER_NAME, PASSWORD,
            body_text, server=SMTP_SERVER, port=SMTP_PORT, logger=logger)
    if result:
        if logger:
            logger.info('Send email successfully')
        return True
    else:
        if logger:
            logger.error('Send email unsuccessfully')
        return False

if __name__ == '__main__':

    main(LOGGER)
