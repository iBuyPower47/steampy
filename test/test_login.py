from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from steampy.login import LoginExecutor


class TestLogin(TestCase):
    def test_encrypt_password_uses_utf8_encoding(self):
        executor = LoginExecutor('user', 'pässword', 'secret', Mock())
        rsa_params = SimpleNamespace(publickey_exp='10001', publickey_mod='af')

        with patch('steampy.login.rsa.PublicKey') as public_key_mock, patch('steampy.login.rsa.encrypt') as encrypt_mock:
            encrypt_mock.return_value = b'encrypted'

            encoded_password = executor._encrypt_password_protobuf(rsa_params)

        public_key_mock.assert_called_once_with(n=int('af', 16), e=int('10001', 16))
        encrypt_mock.assert_called_once_with(message='pässword'.encode('utf-8'), pub_key=public_key_mock.return_value)
        self.assertEqual(encoded_password, 'ZW5jcnlwdGVk')
