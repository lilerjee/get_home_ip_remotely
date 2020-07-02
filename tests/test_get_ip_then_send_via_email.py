import unittest

from get_home_ip_remotely.get_ip_then_send_via_email import get_ip_from_router
from get_home_ip_remotely.get_ip_then_send_via_email import encrypt_text
from get_home_ip_remotely.get_ip_then_send_via_email import send_mail
from get_home_ip_remotely.get_ip_then_send_via_email import main
from get_home_ip_remotely.config import (SEND_FROM, SEND_TO,
        USER_NAME, PASSWORD, SMTP_SERVER, SMTP_PORT, EMAIL_TAG, SALT)


class TestGetIpFromRouter(unittest.TestCase):

    def test_router_ip_url_empty(self):
        router_ip_url=''
        authorization_headers={
            'Authorization': 'Basic YWRtaW46SklNNDgxNDg2MGppbQ=='}
        ip_regex=r'wanPara\s+=\s+new\s+Array\(.*?"(\d+\.\d+\.\d+\.\d+)",'

        self.assertRaises(AssertionError, get_ip_from_router, router_ip_url,
                authorization_headers, ip_regex, logger=None)

    def test_authorization_headers_empty(self):
        router_ip_url='http://192.168.0.1/userRpm/StatusRpm.htm'
        authorization_headers={}
        ip_regex=r'wanPara\s+=\s+new\s+Array\(.*?"(\d+\.\d+\.\d+\.\d+)",'

        self.assertRaises(AssertionError, get_ip_from_router, router_ip_url,
                authorization_headers, ip_regex, logger=None)

    def test_ip_regex_empty(self):
        router_ip_url='http://192.168.0.1/userRpm/StatusRpm.htm'
        authorization_headers={
            'Authorization': 'Basic YWRtaW46SklNNDgxNDg2MGppbQ=='}
        ip_regex=''

        self.assertRaises(AssertionError, get_ip_from_router, router_ip_url,
                authorization_headers, ip_regex, logger=None)

    def test_normal_value(self):
        router_ip_url='http://192.168.0.1/userRpm/StatusRpm.htm'
        authorization_headers={
            'Authorization': 'Basic YWRtaW46SklNNDgxNDg2MGppbQ=='}
        ip_regex=r'wanPara\s+=\s+new\s+Array\(.*?"(\d+\.\d+\.\d+\.\d+)",'

        ip = get_ip_from_router(router_ip_url, authorization_headers,
                ip_regex, logger=None)
        self.assertRegex(ip, r'\d+\.\d+\.\d+\.\d+')

class TestSendEmail(unittest.TestCase):

    def test_send_an_email_successfully(self):

        subject = '[test-anything-you-like]'
        #  subject = EMAIL_TAG
        body_text = subject
        result = send_mail(SEND_FROM, SEND_TO, subject, USER_NAME, PASSWORD,
                 body_text, server=SMTP_SERVER, port=SMTP_PORT)
        #  result = send_mail(SEND_FROM, SEND_TO, subject, USER_NAME, PASSWORD,
        #           body_text, server=SMTP_SERVER, port=SMTP_PORT)
        self.assertTrue(result)

class TestEncryptText(unittest.TestCase):

    def decrypt_text(self, encrypted_text, password, salt):

        import base64
        from cryptography.fernet import Fernet
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        text = f.decrypt(encrypted_text)
        return text.decode('utf-8')

    def test_encrypt_then_decrypt_value(self):
        text = 'test text'
        encrypt_password = 'password'.encode(encoding='utf-8')
        #  salt = br'\x66(\x1dkY\x860\xfa\xe8\x82\x1a\xda\x1eG\xf1p'
        salt = SALT

        ciphertext = encrypt_text(text, encrypt_password, salt, None)
        self.assertNotEqual(text, ciphertext)
        text1 = self.decrypt_text(ciphertext, encrypt_password, salt)
        self.assertEqual(text1, text)

class TestMain(unittest.TestCase):

    def test_get_home_ip_and_send_it_is_successful(self):

        result = main(logger=None)
        self.assertTrue(result)

#  if __name__ == '__main__':
#      unittest.main()
