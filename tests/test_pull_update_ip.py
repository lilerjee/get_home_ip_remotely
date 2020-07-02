import os
import unittest
import pwd

from get_home_ip_remotely.pull_update_ip import get_mail_text
from get_home_ip_remotely.pull_update_ip import decrypt_text
from get_home_ip_remotely.pull_update_ip import update_hosts
from get_home_ip_remotely.pull_update_ip import main
from get_home_ip_remotely.get_ip_then_send_via_email import send_mail

from get_home_ip_remotely.config import (SEND_FROM, SEND_TO, USER_NAME,
        PASSWORD, IMAP_SERVER, IMAP_PORT, ENCRYPT_PASSWORD, SALT, EMAIL_TAG,
        SMTP_SERVER, SMTP_PORT, HOSTS_FILE)


class TestGetMailText(unittest.TestCase):

    def test_pull_the_email(self):
        subject = EMAIL_TAG
        body_text = subject
        result = send_mail(SEND_FROM, SEND_TO, subject, USER_NAME, PASSWORD,
                 body_text, server=SMTP_SERVER, port=SMTP_PORT)
        #  result = send_mail(SEND_FROM, SEND_TO, subject, USER_NAME, PASSWORD,
        #           body_text, server=SMTP_SERVER, port=SMTP_PORT)
        self.assertTrue(result)

        subject = get_mail_text(USER_NAME, PASSWORD, IMAP_SERVER,
                IMAP_PORT, return_subject=True, logger=None)
        #  subject = get_mail_text(USER_NAME, PASSWORD, IMAP_SERVER,
        #          IMAP_PORT, return_subject=True)
        self.assertIn(EMAIL_TAG, subject)

class TestDecryptText(unittest.TestCase):

    def test_decrypt_text(self):
        ip_text = get_mail_text(USER_NAME, PASSWORD, IMAP_SERVER,
                IMAP_PORT, False, None)
        ip = decrypt_text(ip_text.encode('utf-8'),
                ENCRYPT_PASSWORD.encode('utf-8'), SALT, None)
        self.assertRegex(ip, r'\d+\.\d+\.\d+\.\d+')

class TestUpdateHosts(unittest.TestCase):

    def setUp(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__))
                ) + os.sep + 'get_home_ip_remotely'
        self.domain_file = self.base_dir + os.sep + 'domain.txt'

        self.hosts_file = self.base_dir + os.sep + 'hosts'
        self.hf = open(self.hosts_file, 'w+')

        self.old_ip = '128.0.0.1'

        self.home_ip_file = self.base_dir + os.sep + 'home_ip.txt'
        if os.path.exists(self.home_ip_file):
            self.pf = open(self.home_ip_file, 'r+')
            self.pf.truncate()
            self.pf.flush()
            self.pf.write(self.old_ip)
            self.pf.flush()
            self.pf.close()

        self.test_domain = 'testdomain.com'
        self.test_domain1 = 'testdomain1.com'
        self.test_ip = '127.0.0.1'

        self.df = open(self.domain_file, 'a+')
        self.df.write('{}'.format(self.test_domain))
        self.df.flush()

    def tearDown(self):
        self.hf.seek(0)
        self.df.seek(0)

        lines = self.df.readlines()[:-1]
        self.df.seek(0)
        self.df.truncate()
        self.df.writelines(lines)
        self.df.close()

        if self.hosts_file.strip() != '/etc/hosts':
            self.hf.close()
            os.remove(self.hosts_file)
        else:
            lines = self.hf.readlines()[:-1]
            self.hf.seek(0)
            self.hf.truncate()
            self.hf.writelines(lines)
            self.hf.close()

    def test_update_domain_in_domain_file(self):

        result = update_hosts(self.test_ip, self.hosts_file, None)

        self.hf.seek(0)
        lines = self.hf.readlines()[0]
        self.assertIn(self.test_domain, lines)
        self.assertTrue(result)

    def test_update_domain_in_domain_file_and_in_hosts(self):

        hf = open(self.hosts_file, 'w')
        hf.write('{}\t{}\n'.format(self.old_ip, self.test_domain1))
        hf.flush()
        hf.close()
        
        #  result = update_hosts(self.test_ip, self.hosts_file)
        result = update_hosts(self.test_ip, self.hosts_file, None)

        self.assertTrue(result)

        self.hf.seek(0)
        lines = self.hf.readlines()
        #  print('lines: {}'.format(lines))
        self.assertIn(self.test_domain1, lines[0])
        self.assertIn(self.test_domain, lines[1])

@unittest.skipUnless(pwd.getpwuid(os.getuid()).pw_name == 'root',
        'require root right')
class TestMain(unittest.TestCase):

    # Run it with root right
    def test_pull_update_ip_is_successful(self):
        result = main(HOSTS_FILE, logger=None)
        self.assertTrue(result)



#  if __name__ == '__main__':
#      unittest.main()

