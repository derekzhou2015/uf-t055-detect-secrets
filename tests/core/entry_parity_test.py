"""
Regression tests for uf-t055: the CLI entry point and the library entry point
must report the same secrets for the same content.

Root cause of the divergence: the CLI registers
`detect_secrets.filters.common.is_ignored_due_to_verification_policies` with
`min_level=UNVERIFIED` by default, and the old filter implementation dropped
anything scoring *below* that level — silently swallowing VERIFIED_FALSE
secrets (e.g. leaked-then-revoked credentials). Library scans through
`default_settings()` register no such filter, so they reported those secrets.
The filter now drops nothing unless the strict `--only-verified` policy is
requested.

This matrix runs fully offline: the CLI side is invoked with `--no-verify`,
and the gibberish filter (an anti-false-positive mechanism that the real CLI
enables when the optional `gibberish-detector` package is installed, but that
`default_settings()` does not) is disabled on both sides so the comparison is
apples-to-apples.
"""
import json

import pytest

from detect_secrets import main as main_module
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import default_settings
from testing.mocks import disable_gibberish_filter
from testing.mocks import mock_printer


# One sample, several secret types that both entry points must agree on.
# NOTE: the GitHub tokens exercise the GitHubTokenDetector fix (the classic
# pattern's capturing group used to record only `ghp` as the secret value,
# and fine-grained PATs were not detected at all). Token bodies are built
# programmatically so their lengths are correct by construction.
GITHUB_CLASSIC_TOKEN = 'ghp_' + 'wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx'
GITHUB_FINE_GRAINED_PAT = 'github_pat_' + 'a1' * 11 + '_' + 'b2' * 29 + 'c'
SAMPLE_LINES = [
    'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
    'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    f'github_token = "{GITHUB_CLASSIC_TOKEN}"',
    f'github_fine_grained = "{GITHUB_FINE_GRAINED_PAT}"',
    'slack_token = "xoxb-123456789012-123456789012-wWPw5k4aXcaT4fNP0UcnZw"',
]
SAMPLE_FILENAME = 'parity_sample.txt'


def _scan_via_library(filename: str) -> set:
    """The library entry point: `default_settings()` + SecretsCollection."""
    with default_settings():
        collection = SecretsCollection()
        collection.scan_file(filename)

    return {
        (secret.type, secret.line_number, secret.secret_hash)
        for _, secret in collection
    }


def _scan_via_cli(filename: str) -> set:
    """The CLI entry point: `detect-secrets scan --no-verify <file>`."""
    with disable_gibberish_filter(), mock_printer(main_module) as printer:
        main_module.main(['scan', '--no-verify', filename])

    output = json.loads(printer.message)
    return {
        (result['type'], result['line_number'], result['hashed_secret'])
        for results in output['results'].values()
        for result in results
    }


@pytest.fixture()
def sample_file(tmp_path, monkeypatch):
    # NOTE: scan from a *relative* path inside tmp_path. Absolute paths (e.g.
    # into the temp drive) can be silently skipped by `get_files_to_scan`,
    # which would make this test compare two empty result sets.
    sample = tmp_path / SAMPLE_FILENAME
    sample.write_text('\n'.join(SAMPLE_LINES) + '\n')
    monkeypatch.chdir(tmp_path)
    return SAMPLE_FILENAME


def test_cli_and_library_report_same_secrets(sample_file):
    library_results = _scan_via_library(sample_file)
    cli_results = _scan_via_cli(sample_file)

    # The matrix only means something if the sample actually flags secrets.
    assert len(library_results) > 0

    # The CLI must never silently drop a secret the library reports...
    assert cli_results >= library_results
    # ...and both entry points share one detection standard: full equality.
    assert cli_results == library_results


def test_github_tokens_detected_as_whole_values(sample_file):
    """Both GitHub token formats must survive end-to-end through both entries."""
    library_results = _scan_via_library(sample_file)
    cli_results = _scan_via_cli(sample_file)

    for results in (library_results, cli_results):
        github_hits = [r for r in results if r[0] == 'GitHub Token']
        assert len(github_hits) == 2
