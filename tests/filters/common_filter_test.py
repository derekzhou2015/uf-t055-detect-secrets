import re
from unittest import mock

import pytest
import requests

from detect_secrets import main as main_module
from detect_secrets.constants import VerifiedResult
from detect_secrets.plugins.base import RegexBasedDetector
from testing.mocks import mock_printer
from testing.plugins import register_plugin


class TestVerify:
    @staticmethod
    def test_does_not_verify_if_no_verify():
        with register_plugin(MockPlugin(should_verify=False)):
            main_module.main(['scan', '--string', 'deadbeef', '--no-verify'])

    @staticmethod
    @pytest.mark.parametrize(
        'args, verified_result, should_be_present',
        (
            ([], VerifiedResult.UNVERIFIED, True),
            ([], VerifiedResult.VERIFIED_TRUE, True),
            # A leaked-then-revoked secret is still a finding: the default
            # policy must report it, not silently swallow it (uf-t055).
            ([], VerifiedResult.VERIFIED_FALSE, True),
            (['--only-verified'], VerifiedResult.UNVERIFIED, False),
            (['--only-verified'], VerifiedResult.VERIFIED_TRUE, True),
            (['--only-verified'], VerifiedResult.VERIFIED_FALSE, False),
        ),
    )
    def test_adheres_to_verification_policies(args, verified_result, should_be_present):
        with register_plugin(
            MockPlugin(verified_result=verified_result),
        ), mock_printer(main_module) as printer:
            main_module.main(['scan', '--string', 'deadbeef', *args])

        found = False
        for line in printer.message.splitlines():
            plugin_name, result = [x.strip() for x in line.split(':')]
            if plugin_name != 'MockPlugin':
                continue

            found = True
            # `False` means "not flagged". `False (verified)` means the secret
            # WAS flagged, and verification proved it invalid — still reported.
            assert should_be_present == (result != 'False')

        assert found

    @staticmethod
    @pytest.mark.parametrize('args', ([], ['--only-verified']))
    def test_request_error_never_drops_secret(args):
        # A network error during verification says nothing about the secret:
        # it must be reported under every policy (uf-t055).
        with register_plugin(
            ExceptionRaisingMockPlugin(),
        ), mock_printer(main_module) as printer:
            main_module.main(['scan', '--string', 'deadbeef', *args])

        found = False
        for line in printer.message.splitlines():
            plugin_name, result = [x.strip() for x in line.split(':')]
            if plugin_name != 'ExceptionRaisingMockPlugin':
                continue

            found = True
            assert result != 'False'

        assert found

    @staticmethod
    def test_supports_injection_of_context():
        # NOTE: This test case relies on the fact that this file contains a multi-factor
        # AWS KeyPair.
        with register_plugin(ContextAwareMockPlugin()):
            with mock.patch(
                'detect_secrets.plugins.aws.verify_aws_secret_access_key',
                return_value=False,
            ):

                main_module.main(['scan', 'test_data/each_secret.py'])

    @staticmethod
    def test_handles_request_error_gracefully():
        with register_plugin(ExceptionRaisingMockPlugin()):
            main_module.main(['scan', '--string', 'fake-secret'])


class MockPlugin(RegexBasedDetector):
    denylist = (
        # We use a hex string here, due to the gibberish detector.
        re.compile('deadbeef'),
    )
    secret_type = 'mock plugin'

    def __init__(self, should_verify=True, verified_result=VerifiedResult.UNVERIFIED):
        self.should_verify = should_verify
        self.verified_result = verified_result

    def verify(self, secret):
        if not self.should_verify:
            raise AssertionError('Verification should not occur.')

        return self.verified_result


class ContextAwareMockPlugin(MockPlugin):
    def verify(self, secret, context):
        return VerifiedResult.UNVERIFIED


class ExceptionRaisingMockPlugin(MockPlugin):
    def verify(self, secret):
        raise requests.exceptions.ConnectionError
