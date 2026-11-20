import pytest

from detect_secrets.plugins.github_token import GitHubTokenDetector


class TestGitHubTokenDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('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', True),
            ('foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx', False),
            ('foo', False),
            # Fine-grained PATs: github_pat_ + 22 alphanumeric chars + _ + 59 alphanumeric
            (
                'github_pat_' + 'a1B2c3D4e5F6g7H8i9J0k1' + '_'
                + ('x9Y8z7W6v5U4t3S2r1Q0p' * 3)[:59],
                True,
            ),
            # A fine-grained PAT with a malformed (too short) tail must not match.
            (
                'github_pat_' + 'a1B2c3D4e5F6g7H8i9J0k1' + '_' + 'x9Y8z7W6v5U4t3S2r1Q0p',
                False,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = GitHubTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)

    @pytest.mark.parametrize(
        'payload, expected_secret',
        [
            (
                "GITHUB_TOKEN = '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'",
                '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',
            ),
            (
                "GITHUB_FINE_GRAINED_PAT = 'github_pat_"
                + 'a1B2c3D4e5F6g7H8i9J0k1' + '_'
                + ('x9Y8z7W6v5U4t3S2r1Q0p' * 3)[:59] + "'",
                'github_pat_' + 'a1B2c3D4e5F6g7H8i9J0k1' + '_'
                + ('x9Y8z7W6v5U4t3S2r1Q0p' * 3)[:59],
            ),
        ],
    )
    def test_extracts_the_full_token_as_the_secret_value(self, payload, expected_secret):
        logic = GitHubTokenDetector()
        secrets = list(logic.analyze_line(filename='mock_filename', line=payload))
        assert len(secrets) == 1
        assert secrets[0].secret_value == expected_secret
