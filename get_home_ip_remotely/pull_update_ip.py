# -*- coding: utf-8 -*-
"""Pull the public IP from email server, decrypt it and update hosts with it."""

import os
import sys
import re
import base64
import imaplib
import email
import logging

from logging import handlers

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

if __name__ == '__main__':
    from config import (USER_NAME, PASSWORD, IMAP_SERVER, IMAP_PORT,
            EMAIL_TAG, ENCRYPT_PASSWORD, SALT, HOSTS_FILE)
else:
    from .config import (USER_NAME, PASSWORD, IMAP_SERVER, IMAP_PORT,
            EMAIL_TAG, ENCRYPT_PASSWORD, SALT, HOSTS_FILE)


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

def get_mail_text(user_name, password, server, port=993,
        return_subject=False, logger=LOGGER):
    """Get the email which has home IP.

    Not only get the email, but also delete the old emails.

    :param str user_name: user name of email account.
    :param str password: password of email account.
    :param str server: email IMAP server IP or domain.
    :param int port: email IMAP server port.
    :param bool return_subject: return subject or not.
    """

    server = imaplib.IMAP4_SSL(server, port=port)
    server.login(user_name, password)
    server.select('INBOX')

    if logger:
        logger.info('Get all mail id')
    status, msg_ids = server.search(None, 'ALL')
    if status == 'OK':
        msg_ids = msg_ids[0].decode('utf-8')
    else:
        if logger:
            logger.error('Cannot get mail: %s - %s' % (status, msg_ids))

    msg_ids = msg_ids.split()
    msg_ids = [int(e) for e in msg_ids]
    msg_ids.sort(reverse=True)
    if logger:
        logger.info('All mail ids:\n%s' % msg_ids)

    if logger:
        logger.info('Search the specific mail')
    ip_text = ''
    first = True
    first_subject = ''
    for msg_id in msg_ids:
        status, data = server.fetch(str(msg_id), '(RFC822)')
        #  logger.info('data: %s' % data)
        if not data or not data[0]:
            continue
        raw_email = data[0][1]
        #continue inside the same for loop as above
        #  raw_email_string = raw_email.decode('utf-8')
        # converts byte literal to string removing b''
        email_message = email.message_from_bytes(raw_email)
        if email_message['Subject'] is None:
            server.store(str(msg_id), '+FLAGS', r'(\Deleted)')
            if logger:
                logger.info('Delete the email: %s' % str(server.expunge()))
            continue

        subject_tuple = email.header.decode_header(
            email_message['Subject'])[0]
        #  logger.info(subject_tuple)  # test
        try:
            subject = (subject_tuple[0].decode(subject_tuple[1])
                    if subject_tuple[1] else subject_tuple[0])

            if re.search(r'\r\n', subject):
                subject = re.sub(r'\r\n', '', subject)
                subject_tuple = email.header.decode_header(subject)[0]
                subject = (subject_tuple[0].decode(subject_tuple[1])
                        if subject_tuple[1] else subject_tuple[0])
        except Exception as e:
            try:
                subject = subject_tuple[0].decode('gbk', errors='ignore')
            except Exception as e1:
                if logger:
                    logger.error(
                        '{}: {}'.format('subject_tuple', subject_tuple))  # test
                    logger.error('Error happened level 1: %s' % e)
                    logger.error('Error happened level 2: %s' % e1)
                import traceback
                traceback.print_exc()
                continue

        if re.search(r'\?gb2312\?', subject):
            if logger:
                logger.error('{}: {}'.format(
                    'original subject', email_message['Subject']))  # test
                logger.error(
                    '{}: {}'.format('subject_tuple', subject_tuple))  # test

        date = email_message['Date']
        #  logger.info('Subject: %s' % subject)
        #  logger.info('Date: %s' % date)
        #  m = re.search('^\[my-net]\s+(.*)', subject)
        #  m = re.search('^' + re.escape(EMAIL_TAG) + '\s+(.*)', subject)
        m = re.search(re.escape(EMAIL_TAG) + '\s*(.*)', subject)
        if m:
            text = m.groups()[0]
            if first:
                ip_text = text
                first_subject = subject
                if logger:
                    logger.info('Date: %s' % date)
                    logger.info('Subject: %s' % subject)
                #  logger.info('Get the lasted ip encrypted_text:\n%s' % text)
                first = False
            else:
                # delete the email
                server.store(str(msg_id), '+FLAGS', r'(\Deleted)')
                if logger:
                    logger.info('Delete the email: %s' % str(server.expunge()))
    if logger:
        logger.info('ip_text: {}'.format(ip_text))
    server.close()
    server.logout()

    if return_subject:
        return first_subject
    return ip_text

def decrypt_text(encrypted_text, encrypted_password, salt, logger=LOGGER):
    """Decrypt text with password and salt.

    Example::

        salt = b'\\x66(\\x1dkY\\x860\\xfa\\xe8\\x82\\x1a\\xda\\x1eG\\xf1p'


    :param bytes encrypted_password: password to generate a key.
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
    key = base64.urlsafe_b64encode(kdf.derive(encrypted_password))
    f = Fernet(key)
    text = f.decrypt(encrypted_text)
    text = text.decode('utf-8')
    if logger:
        logger.info('decrypted_text: {}'.format(text))
    return text

def update_hosts(ip, hosts_file='/etc/hosts', logger=LOGGER):
    """Update home IP for domains in hosts file.

    home_ip.txt
        save the new home ip, just one line.

    domain.txt
        contain the domains for home ip, one domain per line,
        and can comment one line with #.

    :param str ip: IP to be updated.
    :param str hosts_file: hosts file path.

    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    home_ip_file = base_dir + os.sep + 'home_ip.txt'
    domain_file = base_dir + os.sep + 'domain.txt'

    hf = open(hosts_file, 'r+')
    pf_existed = True
    if os.path.exists(home_ip_file):
        pf = open(home_ip_file, 'r+')
    else:
        # Not existed, the create it.
        pf = open(home_ip_file, 'w+')
        pf_existed = False


    #  logger.info('hosts file in main: {}'.format(hosts_file))
    #  logger.info('hosts: {}'.format(hf.read()))

    # You need create domain file manually
    if os.path.exists(domain_file):
        df = open(domain_file, 'r')
    else:
        df = None
        if logger:
            logger.warning('There is no file: {}'.format(domain_file))
        if not pf_existed:
            logger.error("There are't both files: {} - {}".format(
                home_ip_file, domain_file))
            hf.close()
            pf.close()
            return False

    old_ip = pf.readline().strip()
    if logger:
        logger.info('Old IP: {}'.format(old_ip))
    # Both old IP and domain file cannot missed.
    # You should config domain file first.
    if not old_ip and not df:
        if logger:
            logger.error("There is no file: {}, and have no old IP in"
                    " the file {}.".format(domain_file, home_ip_file))
        hf.close()
        pf.close()
        return False

    if old_ip:
        if ip == old_ip:
            if logger:
                logger.info('The IP is not changed.')
            df.close()
            hf.close()
            pf.close()
            return False
            #  sys.exit(0)

        content = ''
        domains = set()
        for line in hf:
            m = re.match(r'^\s*%s\s+(.*)$' % old_ip, line)
            if m:
                domain = m.groups()[0]
                domain = domain.strip()
                if logger:
                    logger.info(
                        'Find ip domain map: (%s - %s)' % (old_ip, domain))
                content += '%s\t%s\n' % (ip, domain)
                domains.add(domain)
            else:
                content += line
        if logger:
            logger.info('Modified content of hosts: {}'.format(content))

        # get domains from domain_file
        if df:
            domains_from_file = set()
            for line in df:
                # can comment line with #
                m = re.match(r'^\s*([^#]+)', line)
                if m:
                    domain = m.groups()[0]
                    domain = domain.strip()
                    if logger:
                        logger.info('find domain in domain_file: {}'.format(
                            domain))
                    domains_from_file.add(domain)

            if logger:
                logger.info('domains_from_file: {}, domains in hosts: {}'
                        ''.format(domains_from_file, domains))
            domain_not_in_hosts = domains_from_file - domains
            for d in domain_not_in_hosts:
                content += '%s\t%s\n' % (ip, domain)
            df.close()

    else:
        # No old ip, then read the domain file,
        # and update hosts with the domains and new IP.
        content = hf.read()
        for line in df:
            m = re.match(r'^\s*([^#]+)', line)
            if m:
                domain = m.groups()[0]
                if logger:
                    logger.info('find domain in domain_file: {}'.format(
                        domain))
                content += '%s\t%s\n' % (ip, domain)
        df.close()

    hf.seek(0)
    hf.truncate()
    hf.write(content)
    hf.close()
    if logger:
        logger.info('Change the IP to %s successfully' % ip)

    pf.seek(0)
    pf.truncate()
    pf.write(ip)
    pf.close()
    if logger:
        logger.info('Save the new IP into {}'.format(home_ip_file))
    return True

def main(hosts_file='/etc/hosts', logger=LOGGER):
    """Get encrypted text from email server, decrypt it, and update hosts with it."""

    encrypted_text = get_mail_text(USER_NAME, PASSWORD, IMAP_SERVER,
            IMAP_PORT, logger=logger)
    if encrypted_text:
        ip = decrypt_text(
            encrypted_text.encode('utf-8'),
            ENCRYPT_PASSWORD.encode('utf-8'), SALT, logger=logger)
        if logger:
            logger.info('The new IP: %s' % ip)

        #  hosts_file = 'c:/Windows/System32/drivers/etc/hosts'
        #  hosts_file = '/etc/hosts'
        update_hosts(ip, hosts_file, logger=logger)
        return True
    else:
        if logger:
            logger.info('Cannot find IP email')
        return False


if __name__ == '__main__':
    main(HOSTS_FILE, LOGGER)
