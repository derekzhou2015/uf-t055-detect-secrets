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

    NOTE: Under the default policy (min_level=UNVERIFIED) this filter drops nothing.
    A secret that verifies as VERIFIED_FALSE is still reported: it may be a
    leaked-then-revoked credential, which is exactly what an audit needs to surface.
    Dropping it here also made the CLI entry point disagree with library scans through
    `default_settings()`, which register no verification filter at all. Only the strict
    `--only-verified` policy (min_level=VERIFIED_TRUE) filters anything out.
    """
    if _get_verification_policy() != VerifiedResult.VERIFIED_TRUE:
        return False

    try:
        verify_result = call_function_with_arguments(
            plugin.verify,
            secret=secret,
            context=context,
        )
    except requests.exceptions.RequestException:
        # A network error tells us nothing about the secret: don't silently drop it.
        return False

    return verify_result != VerifiedResult.VERIFIED_TRUE


@lru_cache(maxsize=1)
def _get_verification_policy() -> VerifiedResult:
    path = get_caller_path(offset=1)
    return VerifiedResult(get_settings().filters[path]['min_level'])
