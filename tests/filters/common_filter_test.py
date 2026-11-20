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
            (['--only-verified'], VerifiedResult.UNVERIFIED, False),
            (['--only-verified'], VerifiedResult.VERIFIED_TRUE, True),
        ),
    )
    def test_adheres_to_verification_policies(args, verified_result, should_be_present):
        with register_plugin(
            MockPlugin(verified_result=verified_result),
        ), mock_printer(main_module) as printer:
            main_module.main(['scan', '--string', 'deadbeef', *args])

        for line in printer.message.splitlines():
            plugin_name, result = [x.strip() for x in line.split(':')]
            if plugin_name != 'MockPlugin':
                continue

            assert should_be_present == result.startswith('True')

    @staticmethod
    def test_verified_false_secret_is_reported_not_silently_dropped():
        # Regression: under the default verification policy, VERIFIED_FALSE secrets (e.g.
        # leaked-then-revoked credentials) used to be silently discarded by the CLI entry
        # point, while the library entry point reported them. They must now remain visible
        # (labelled as verified false) instead of vanishing without a trace.
        with register_plugin(
            MockPlugin(verified_result=VerifiedResult.VERIFIED_FALSE),
        ), mock_printer(main_module) as printer:
            main_module.main(['scan', '--string', 'deadbeef'])

        verdicts = {
            plugin_name.strip(): result.strip()
            for line in printer.message.splitlines()
            for plugin_name, result in [line.split(':')]
        }
        assert verdicts['MockPlugin'] == 'False (verified)'

        # And with the strict policy the same finding is suppressed: in adhoc scans every
        # plugin prints a line, but its verdict must no longer be truthy.
        with register_plugin(
            MockPlugin(verified_result=VerifiedResult.VERIFIED_FALSE),
        ), mock_printer(main_module) as strict_printer:
            main_module.main(['scan', '--string', 'deadbeef', '--only-verified'])

        strict_verdicts = {
            plugin_name.strip(): result.strip()
            for line in strict_printer.message.splitlines()
            for plugin_name, result in [line.split(':')]
        }
        assert not strict_verdicts['MockPlugin'].startswith('True')

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


class TestVerificationPolicyFilter:
    """Direct contract tests for is_ignored_due_to_verification_policies."""

    @staticmethod
    @pytest.mark.parametrize(
        'min_level, verified_result, expected_filtered',
        (
            # Only the strict VERIFIED_TRUE policy may suppress findings.
            (VerifiedResult.VERIFIED_TRUE, VerifiedResult.VERIFIED_TRUE, False),
            (VerifiedResult.VERIFIED_TRUE, VerifiedResult.VERIFIED_FALSE, True),
            (VerifiedResult.VERIFIED_TRUE, VerifiedResult.UNVERIFIED, True),

            # The default CLI policy (UNVERIFIED) keeps everything the library reports.
            (VerifiedResult.UNVERIFIED, VerifiedResult.VERIFIED_FALSE, False),
            (VerifiedResult.UNVERIFIED, VerifiedResult.UNVERIFIED, False),
            (VerifiedResult.UNVERIFIED, VerifiedResult.VERIFIED_TRUE, False),
        ),
    )
    def test_only_verified_true_policy_suppresses_findings(
        min_level,
        verified_result,
        expected_filtered,
    ):
        from detect_secrets.filters.common import is_ignored_due_to_verification_policies
        from detect_secrets.settings import transient_settings

        plugin = MockPlugin(verified_result=verified_result)
        config = {
            'filters_used': [{
                'path': 'detect_secrets.filters.common.is_ignored_due_to_verification_policies',
                'min_level': min_level.value,
            }],
        }
        with transient_settings(config):
            filtered = is_ignored_due_to_verification_policies(
                secret='deadbeef',
                plugin=plugin,
                context=None,
            )
        assert filtered is expected_filtered

    @staticmethod
    def test_request_errors_never_cause_a_secret_to_be_dropped():
        from detect_secrets.filters.common import is_ignored_due_to_verification_policies
        from detect_secrets.settings import transient_settings

        config = {
            'filters_used': [{
                'path': 'detect_secrets.filters.common.is_ignored_due_to_verification_policies',
                'min_level': VerifiedResult.VERIFIED_TRUE.value,
            }],
        }
        with transient_settings(config):
            filtered = is_ignored_due_to_verification_policies(
                secret='fake-secret',
                plugin=ExceptionRaisingMockPlugin(),
                context=None,
            )
        assert filtered is False


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
