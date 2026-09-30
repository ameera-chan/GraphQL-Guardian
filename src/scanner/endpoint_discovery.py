"""GraphQL endpoint discovery by probing common paths.

Given a base URL (e.g. ``http://target.com``), this module iterates over a
curated list of well-known GraphQL paths and checks each one for a valid
GraphQL response.  The check mirrors graphw00f's approach: send a
``{ __typename }`` query and look for a valid ``data`` or ``errors`` payload.
"""

from __future__ import annotations

import logging
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

from src.config import GRAPHQL_ENDPOINT_PATHS

logger = logging.getLogger(__name__)


class EndpointDiscovery:
    """Probe common paths on a host to discover GraphQL endpoints.

    Usage::

        discovery = EndpointDiscovery("http://target.com")
        endpoints = discovery.run()
        for ep in endpoints:
            print(ep)  # e.g. http://target.com/graphql
    """

    TYPENAME_QUERY = 'query { __typename }'

    def __init__(
        self,
        base_url: str,
        headers: Optional[Dict] = None,
        timeout: int = 10,
        proxy: Optional[str] = None,
        paths: Optional[List[str]] = None,
    ):
        """
        Args:
            base_url: The root URL of the target (e.g. ``http://target.com``).
            headers:  Optional HTTP headers to include in every probe.
            timeout:  Per-request timeout in seconds.
            proxy:    Optional proxy URL (e.g. ``http://127.0.0.1:8080``).
            paths:    Custom list of paths to probe.  Defaults to the
                      built-in :data:`GRAPHQL_ENDPOINT_PATHS`.
        """
        # Normalise base_url: strip any existing path so we can append ours
        parsed = urlparse(base_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.headers = headers or {'Content-Type': 'application/json'}
        self.timeout = timeout
        self.proxies = {'http': proxy, 'https': proxy} if proxy else None
        self.paths = paths or list(GRAPHQL_ENDPOINT_PATHS)

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _is_graphql(self, url: str) -> bool:
        """Return True if *url* responds like a GraphQL endpoint."""
        try:
            resp = requests.post(
                url,
                json={'query': self.TYPENAME_QUERY},
                headers=self.headers,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=not bool(self.proxies),
            )
            data = resp.json()
            # Valid GraphQL if we get a data or errors key with proper structure
            if data.get('data'):
                typename = data.get('data', {}).get('__typename', '')
                if typename in ('Query', 'QueryRoot', 'query_root'):
                    return True
            if data.get('errors') and isinstance(data['errors'], list):
                if any('locations' in e for e in data['errors']) or any('extensions' in e for e in data['errors']):
                    return True
            if data.get('data') is not None:
                return True
        except Exception:
            pass

        # Fallback: try GET
        try:
            resp = requests.get(
                url,
                params={'query': self.TYPENAME_QUERY},
                headers=self.headers,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=not bool(self.proxies),
            )
            data = resp.json()
            if data.get('data') or (data.get('errors') and isinstance(data['errors'], list)):
                return True
        except Exception:
            pass

        return False

    # ── Public API ───────────────────────────────────────────────────────────

    def run(self) -> List[str]:
        """Probe all candidate paths and return a list of discovered endpoints."""
        discovered: List[str] = []
        for path in self.paths:
            url = urljoin(self.base_url + '/', path.lstrip('/'))
            logger.debug("Probing %s ...", url)
            try:
                if self._is_graphql(url):
                    discovered.append(url)
                    logger.info("GraphQL endpoint found: %s", url)
            except Exception as exc:
                logger.debug("Probe %s failed: %s", url, exc)
        return discovered
