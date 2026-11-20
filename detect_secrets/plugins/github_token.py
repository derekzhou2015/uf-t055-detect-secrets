"""
This plugin searches for GitHub tokens
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class GitHubTokenDetector(RegexBasedDetector):
    """Scans for GitHub tokens."""
    secret_type = 'GitHub Token'

    denylist = [
        # ref. https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
        # NOTE: This must be a non-capturing group: `RegexBasedDetector.analyze_string`
        # uses `re.findall`, which yields the *group* (not the whole match) when the
        # pattern captures — so a capturing group here would record `ghp` as the secret
        # instead of the full token.
        re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}'),
        # Fine-grained personal access tokens:
        # `github_pat_` + 22 alphanumerics + `_` + 59 alphanumerics.
        re.compile(r'github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}'),
    ]
