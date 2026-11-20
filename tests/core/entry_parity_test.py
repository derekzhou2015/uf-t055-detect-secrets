"""
Parity between the two supported entry points into the scanning engine:

1. the command line entry point (``detect-secrets scan``, driven through ``main.main``)
2. the library entry point (``SecretsCollection.scan_file`` under ``default_settings``)

The acceptance matrix runs entirely offline: network-based verification is disabled via the
``--no-verify`` CLI flag (and the library entry point never registers the verification
filter), so no socket is opened and the same set of plugins/filters decides the findings.
"""
import json

from detect_secrets import main as main_module
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import default_settings
from testing.mocks import disable_gibberish_filter
from testing.mocks import mock_printer

FINE_GRAINED_PAT = (
    'github_pat_'
    + 'a1B2c3D4e5F6g7H8i9J0k1'
    + '_'
    + ('x9Y8z7W6v5U4t3S2r1Q0p' * 3)[:59]
)

# Minimal sample that exercises every gap this test guards:
#   - classic AWS key (verification-policy swallowing used to hide it from the CLI)
#   - classic GitHub token (capturing-group bug used to truncate the secret to "ghp")
#   - fine-grained GitHub PAT (previously not detected by either entry point)
SAMPLE_LINES = (
    "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
    "GITHUB_TOKEN = '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'\n"
    "GITHUB_FINE_GRAINED_PAT = '" + FINE_GRAINED_PAT + "'\n"
)
SAMPLE_FILENAME = 'sample_secrets.py'


def _identifiers(results):
    """(filename, type, line_number, hashed_secret) tuples, order-insensitive."""
    return {
        (
            filename,
            secret['type'],
            secret['line_number'],
            secret['hashed_secret'],
        )
        for filename, secrets in results.items()
        for secret in secrets
    }


def _scan_via_cli():
    with disable_gibberish_filter(), mock_printer(main_module) as printer:
        assert main_module.main(['scan', '--no-verify', SAMPLE_FILENAME]) == 0
    return json.loads(printer.message)['results']


def _scan_via_library():
    with default_settings():
        collection = SecretsCollection()
        collection.scan_file(SAMPLE_FILENAME)
    return collection.json()


class TestEntryPointParity:
    @staticmethod
    def test_cli_and_library_report_identical_findings(tmp_path, monkeypatch):
        (tmp_path / SAMPLE_FILENAME).write_text(SAMPLE_LINES)
        monkeypatch.chdir(tmp_path)

        cli = _scan_via_cli()
        library = _scan_via_library()

        assert _identifiers(cli) == _identifiers(library)

    @staticmethod
    def test_cli_does_not_silently_drop_library_findings(tmp_path, monkeypatch):
        # The acceptance rule is one-directional and must hold on its own:
        # the CLI entry point may not under-report relative to the library entry point.
        (tmp_path / SAMPLE_FILENAME).write_text(SAMPLE_LINES)
        monkeypatch.chdir(tmp_path)

        assert _identifiers(_scan_via_library()) <= _identifiers(_scan_via_cli())

    @staticmethod
    def test_aws_key_survives_in_cli(tmp_path, monkeypatch):
        # Regression: a VERIFIED_FALSE-capable detector's finding used to be swallowed by the
        # CLI's default verification policy, while the library reported it.
        (tmp_path / SAMPLE_FILENAME).write_text(SAMPLE_LINES)
        monkeypatch.chdir(tmp_path)

        findings = _scan_via_cli()
        assert any(
            secret['type'] == 'AWS Access Key'
            for secrets in findings.values()
            for secret in secrets
        )

    @staticmethod
    def test_both_github_token_formats_detected_in_both_entry_points(tmp_path, monkeypatch):
        (tmp_path / SAMPLE_FILENAME).write_text(SAMPLE_LINES)
        monkeypatch.chdir(tmp_path)

        for entry_point, results in (
            ('cli', _scan_via_cli()),
            ('library', _scan_via_library()),
        ):
            github_secrets = [
                secret['line_number']
                for secrets in results.values()
                for secret in secrets
                if secret['type'] == 'GitHub Token'
            ]
            assert github_secrets == [2, 3], entry_point

    @staticmethod
    def test_cli_hashes_the_full_classic_token_not_just_its_prefix(tmp_path, monkeypatch):
        # Regression: the capturing group in the old regex made the secret value "ghp",
        # so every classic token hashed identically regardless of the actual token.
        (tmp_path / SAMPLE_FILENAME).write_text(SAMPLE_LINES)
        monkeypatch.chdir(tmp_path)

        expected_hash = PotentialSecret.hash_secret(
            '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',
        )
        findings = _scan_via_cli()
        assert any(
            secret['type'] == 'GitHub Token'
            and secret['line_number'] == 2
            and secret['hashed_secret'] == expected_hash
            for secrets in findings.values()
            for secret in secrets
        )

        # Sanity check: the truncated prefix must no longer be what gets hashed.
        assert expected_hash != PotentialSecret.hash_secret('ghp')
