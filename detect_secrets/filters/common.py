import os
from functools import lru_cache
from typing import cast

import requests

from ..constants import VerifiedResult
from ..core.plugins import Plugin
from ..settings import get_settings
from ..util.code_snippet import CodeSnippet
from ..util.inject import call_function_with_arguments
from .util import get_caller_path


def is_invalid_file(filename: str) -> bool:
    return not os.path.isfile(filename)


def is_baseline_file(filename: str) -> bool:
    return os.path.basename(filename) == _get_baseline_filename()


@lru_cache(maxsize=1)
def _get_baseline_filename() -> str:
    path = get_caller_path(offset=1)
    return cast(str, get_settings().filters[path]['filename'])


def is_ignored_due_to_verification_policies(
    secret: str,
    plugin: Plugin,
    context: CodeSnippet,
) -> bool:
    """
    Valid policies include:
        - Only VERIFIED_TRUE
        - Can be UNVERIFIED or VERIFIED_TRUE
        - Disabled check.

    There's no such thing as "only verified false", because if you're going to verify
    something, and it's verified false, why are you still including it as a valid secret?

    A looser policy than VERIFIED_TRUE must never discard anything: the library entry point
    (``default_settings``) does not register this filter at all, so having the CLI entry
    point silently drop e.g. VERIFIED_FALSE (leaked-then-revoked) secrets would make the two
    entry points report different sets of findings. Only the explicit ``--only-verified``
    policy (``min_level == VERIFIED_TRUE``) is allowed to suppress findings.
    """
    policy = _get_verification_policy()
    if policy is not VerifiedResult.VERIFIED_TRUE:
        return False

    try:
        verify_result = call_function_with_arguments(
            plugin.verify,
            secret=secret,
            context=context,
        )
    except requests.exceptions.RequestException:
        # We could not verify the secret, so we cannot exclude it.
        return False

    return verify_result is not VerifiedResult.VERIFIED_TRUE


@lru_cache(maxsize=1)
def _get_verification_policy() -> VerifiedResult:
    path = get_caller_path(offset=1)
    return VerifiedResult(get_settings().filters[path]['min_level'])
