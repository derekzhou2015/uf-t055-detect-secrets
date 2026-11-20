import pytest

from detect_secrets.plugins.github_token import GitHubTokenDetector


class TestGitHubTokenDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('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', True),
            # Fine-grained personal access token:
            # `github_pat_` + 22 alphanumerics + `_` + 59 alphanumerics.
            ('github_pat_' + 'a1' * 11 + '_' + 'b2' * 29 + 'c', True),
            # Prefix alone is not enough.
            ('github_pat_' + 'a1' * 11, False),
            ('foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx', False),
            ('foo', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = GitHubTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)

    @pytest.mark.parametrize(
        'token',
        [
            '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',
            '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',
            'ghu_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx',
            'ghs_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx',
            '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',
            'github_pat_' + 'a1' * 11 + '_' + 'b2' * 29 + 'c',
        ],
    )
    def test_whole_token_is_the_secret(self, token):
        # Regression test (uf-t055): the classic pattern used a capturing
        # group, so `re.findall` yielded only the prefix (`ghp`) as the
        # secret value instead of the full token.
        logic = GitHubTokenDetector()
        assert list(logic.analyze_string(token)) == [token]
