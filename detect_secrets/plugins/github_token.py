"""
This plugin searches for GitHub tokens
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class GitHubTokenDetector(RegexBasedDetector):
    """Scans for GitHub tokens."""
    secret_type = 'GitHub Token'

    denylist = [
        # Classic token formats.
        # ref. https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
        #
        # NOTE: use a non-capturing group so that ``re.findall`` yields the *whole* token
        # as the secret value, rather than just the prefix inside the capturing group.
        re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}'),

        # Fine-grained personal access tokens.
        # ref.
        # https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/
        # managing-your-personal-access-tokens#fine-grained-personal-access-tokens
        # Format: ``github_pat_`` + 22 alphanumeric chars + ``_`` + 59 alphanumeric chars.
        re.compile(r'github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}'),
    ]
