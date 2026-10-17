"""Installed version and, for an installation from git, the commit (shown as a badge on the plugin pages)."""
import json
from functools import lru_cache
from importlib import metadata


@lru_cache(maxsize=1)
def plugin_build():
    """{"version", "commit", "short"}; the commit comes from pip's record of an installation from a git URL."""
    from . import __version__

    version, commit = __version__, ''
    try:
        distribution = metadata.distribution('netbox-user-pin')
        version = distribution.version or version
        direct_url = distribution.read_text('direct_url.json')
        commit = (json.loads(direct_url).get('vcs_info') or {}).get('commit_id', '') if direct_url else ''
    except Exception:
        pass
    return {'version': version, 'commit': commit, 'short': commit[:7]}
