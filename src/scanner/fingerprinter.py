"""GraphQL engine fingerprinting via error-message signature matching.

Adapted from graphw00f (https://github.com/dolevf/graphw00f) to work within
the GraphQL Guardian architecture.  Sends deliberately malformed queries and
inspects the returned error strings to identify the backing engine.

Every engine's entry includes a link to the *GraphQL Threat Matrix*
(https://github.com/nicholasaleks/graphql-threat-matrix) so operators can
immediately review the known attack surface for their stack.
"""

from __future__ import annotations

import json
import logging
import requests
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─── Engine Database ───────────────────────────────────────────────────────────

ENGINE_DATABASE: Dict[str, Dict] = {
    'apollo': {
        'name': 'Apollo',
        'url': 'https://www.apollographql.com',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/apollo.md',
        'technology': ['JavaScript', 'Node.js', 'TypeScript'],
    },
    'aws-appsync': {
        'name': 'AWS AppSync',
        'url': 'https://aws.amazon.com/appsync',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/appsync.md',
        'technology': [],
    },
    'graphene': {
        'name': 'Graphene',
        'url': 'https://graphene-python.org',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphene.md',
        'technology': ['Python'],
    },
    'hasura': {
        'name': 'Hasura',
        'url': 'https://hasura.io',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/hasura.md',
        'technology': ['Haskell'],
    },
    'graphql-php': {
        'name': 'GraphQL PHP',
        'url': 'https://webonyx.github.io/graphql-php',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphql-php.md',
        'technology': ['PHP'],
    },
    'ruby-graphql': {
        'name': 'Ruby GraphQL',
        'url': 'https://graphql-ruby.org',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphql-ruby.md',
        'technology': ['Ruby'],
    },
    'ariadne': {
        'name': 'Ariadne',
        'url': 'https://ariadnegraphql.org',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/ariadne.md',
        'technology': ['Python'],
    },
    'wpgraphql': {
        'name': 'WPGraphQL',
        'url': 'https://www.wpgraphql.com',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/wp-graphql.md',
        'technology': ['PHP'],
    },
    'gqlgen': {
        'name': 'gqlgen',
        'url': 'https://gqlgen.com',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/gqlgen.md',
        'technology': ['Go'],
    },
    'graphql-go': {
        'name': 'graphql-go',
        'url': 'https://github.com/graphql-go/graphql',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphql-go.md',
        'technology': ['Go'],
    },
    'graphql-java': {
        'name': 'graphql-java',
        'url': 'https://www.graphql-java.com',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphql-java.md',
        'technology': ['Java'],
    },
    'juniper': {
        'name': 'Juniper',
        'url': 'https://graphql-rust.github.io',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/juniper.md',
        'technology': ['Rust'],
    },
    'sangria': {
        'name': 'Sangria',
        'url': 'https://sangria-graphql.github.io',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/sangria.md',
        'technology': ['Scala'],
    },
    'strawberry': {
        'name': 'Strawberry',
        'url': 'https://github.com/strawberry-graphql/strawberry',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/strawberry.md',
        'technology': ['Python'],
    },
    'tartiflette': {
        'name': 'Tartiflette',
        'url': 'https://github.com/tartiflette/tartiflette',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/tartiflette.md',
        'technology': ['Python'],
    },
    'dgraph': {
        'name': 'Dgraph',
        'url': 'https://dgraph.io/',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/dgraph.md',
        'technology': ['JavaScript'],
    },
    'graphql-yoga': {
        'name': 'GraphQL Yoga',
        'url': 'https://github.com/dotansimha/graphql-yoga',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphql-yoga.md',
        'technology': ['TypeScript'],
    },
    'hypergraphql': {
        'name': 'HyperGraphQL',
        'url': 'https://www.hypergraphql.org',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/hypergraphql.md',
        'technology': ['Java'],
    },
    'graphql-dotnet': {
        'name': 'graphql-dotnet',
        'url': 'https://github.com/graphql-dotnet/graphql-dotnet',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphql-dotnet.md',
        'technology': ['C#', '.NET'],
    },
    'hotchocolate': {
        'name': 'Hot Chocolate',
        'url': 'https://chillicream.com/docs/hotchocolate/v13',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/hotchocolate.md',
        'technology': ['C#', '.NET'],
    },
    'lighthouse': {
        'name': 'Lighthouse',
        'url': 'https://github.com/nuwave/lighthouse',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/lighthouse.md',
        'technology': ['PHP'],
    },
    'mercurius': {
        'name': 'Mercurius',
        'url': 'https://github.com/mercurius-js/mercurius',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/mercurius.md',
        'technology': ['JavaScript', 'Node.js', 'TypeScript'],
    },
    'graphql-api-for-wp': {
        'name': 'GraphQL API for WordPress',
        'url': 'https://graphql-api.com',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphql-api-for-wp.md',
        'technology': ['PHP'],
    },
    'directus': {
        'name': 'Directus',
        'url': 'https://directus.io/',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/directus.md',
        'technology': ['TypeScript'],
    },
    'tailcall': {
        'name': 'Tailcall',
        'url': 'https://tailcall.run',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/tailcall.md',
        'technology': ['Rust'],
    },
    'inigo': {
        'name': 'Inigo',
        'url': 'https://inigo.io',
        'ref': 'https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/inigo.md',
        'technology': ['Go'],
    },
}


@dataclass
class FingerprintResult:
    """Result of an engine-fingerprinting attempt."""
    detected: bool = False
    engine_key: Optional[str] = None
    engine_name: Optional[str] = None
    engine_url: Optional[str] = None
    threat_matrix_url: Optional[str] = None
    technologies: List[str] = field(default_factory=list)


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _error_contains(response: dict, word: str, part: str = 'message') -> bool:
    """Check whether *word* (case-insensitive) appears in response errors."""
    word = word.lower()
    if not isinstance(response, dict):
        return False
    errors = response.get('errors', [])
    if isinstance(errors, list):
        return any(
            word in (err.get(part, '') if isinstance(err, dict) else str(err)).lower()
            for err in errors
        )
    if isinstance(errors, str):
        return word in errors.lower()
    return False


# ─── Fingerprinter ─────────────────────────────────────────────────────────────

class GraphQLFingerprinter:
    """Identify the GraphQL server engine via crafted error-probing queries.

    Usage::

        fp = GraphQLFingerprinter("http://target/graphql")
        result = fp.run()
        print(result.engine_name)  # e.g. "Graphene"
    """

    def __init__(
        self,
        endpoint: str,
        headers: Optional[Dict] = None,
        timeout: int = 10,
        proxy: Optional[str] = None,
    ):
        self.endpoint = endpoint
        self.headers = headers or {'Content-Type': 'application/json'}
        self.timeout = timeout
        self.proxies = {'http': proxy, 'https': proxy} if proxy else None

    # ── Low-level transport ──────────────────────────────────────────────────

    def _query(self, payload: str, operation: str = 'query') -> dict:
        """Send *payload* via both POST and GET; return whichever yields JSON."""
        try:
            resp_post = requests.post(
                self.endpoint,
                json={operation: payload},
                headers=self.headers,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=not bool(self.proxies),
            )
            if isinstance(resp_post.json(), dict):
                return resp_post.json()
        except Exception:
            pass

        try:
            resp_get = requests.get(
                self.endpoint,
                params={operation: payload},
                headers=self.headers,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=not bool(self.proxies),
            )
            if isinstance(resp_get.json(), dict):
                return resp_get.json()
        except Exception:
            pass

        return {}

    # ── Public API ───────────────────────────────────────────────────────────

    def verify_graphql(self) -> bool:
        """Return True if the endpoint appears to serve GraphQL."""
        response = self._query('query { __typename }')
        if response.get('data'):
            typename = response.get('data', {}).get('__typename', '')
            if typename in ('Query', 'QueryRoot', 'query_root'):
                return True
        if response.get('errors') and (
            any('locations' in e for e in response['errors'])
            or any('extensions' in e for e in response['errors'])
        ):
            return True
        if response.get('data'):
            return True
        return False

    def run(self) -> FingerprintResult:
        """Execute all engine probes and return the first match."""
        # The order matters — more specific checks run first.
        checks: List[Tuple[str, callable]] = [
            ('inigo',             self._check_inigo),
            ('lighthouse',        self._check_lighthouse),
            ('graphql-yoga',      self._check_graphql_yoga),
            ('dgraph',            self._check_dgraph),
            ('graphene',          self._check_graphene),
            ('ariadne',           self._check_ariadne),
            ('apollo',            self._check_apollo),
            ('aws-appsync',       self._check_awsappsync),
            ('hasura',            self._check_hasura),
            ('wpgraphql',         self._check_wpgraphql),
            ('graphql-api-for-wp', self._check_graphqlapiforwp),
            ('graphql-java',      self._check_graphqljava),
            ('hypergraphql',      self._check_hypergraphql),
            ('ruby-graphql',      self._check_ruby),
            ('graphql-php',       self._check_graphqlphp),
            ('gqlgen',            self._check_gqlgen),
            ('graphql-go',        self._check_graphqlgo),
            ('juniper',           self._check_juniper),
            ('sangria',           self._check_sangria),
            ('strawberry',        self._check_strawberry),
            ('tartiflette',       self._check_tartiflette),
            ('tailcall',          self._check_tailcall),
            ('directus',          self._check_directus),
            ('mercurius',         self._check_mercurius),
            ('graphql-dotnet',    self._check_graphqldotnet),
            ('hotchocolate',      self._check_hotchocolate),
        ]

        for key, check_fn in checks:
            try:
                if check_fn():
                    info = ENGINE_DATABASE.get(key, {})
                    return FingerprintResult(
                        detected=True,
                        engine_key=key,
                        engine_name=info.get('name', key),
                        engine_url=info.get('url'),
                        threat_matrix_url=info.get('ref'),
                        technologies=info.get('technology', []),
                    )
            except Exception as exc:
                logger.debug("Fingerprint check %s failed: %s", key, exc)

        return FingerprintResult(detected=False)

    # ── Engine Probes ────────────────────────────────────────────────────────
    # Each method sends one or more crafted queries and inspects the error
    # message to identify the engine.  Logic adapted from graphw00f.

    def _check_apollo(self) -> bool:
        r = self._query('query @skip { __typename }')
        if _error_contains(r, 'Directive "@skip" argument "if" of type "Boolean!" is required, but it was not provided.'):
            return True
        r = self._query('query @deprecated { __typename }')
        return _error_contains(r, 'Directive "@deprecated" may not be used on QUERY.')

    def _check_awsappsync(self) -> bool:
        r = self._query('query @skip { __typename }')
        return _error_contains(r, 'MisplacedDirective')

    def _check_graphene(self) -> bool:
        r = self._query('aaa')
        return _error_contains(r, 'Syntax Error GraphQL (1:1)')

    def _check_hasura(self) -> bool:
        r = self._query('query @cached { __typename }')
        if r.get('data', {}).get('__typename', '') == 'query_root':
            return True
        r = self._query('query { aaa }')
        if _error_contains(r, 'field "aaa" not found in type: \'query_root\''):
            return True
        r = self._query('query @skip { __typename }')
        if _error_contains(r, 'directive "skip" is not allowed on a query'):
            return True
        r = self._query('query { __schema }')
        return _error_contains(r, 'missing selection set for "__Schema"')

    def _check_graphqlphp(self) -> bool:
        r = self._query('query ! { __typename }')
        if _error_contains(r, 'Syntax Error: Cannot parse the unexpected character "?".'):
            return True
        r = self._query('query @deprecated { __typename }')
        return _error_contains(r, 'Directive "deprecated" may not be used on "QUERY".')

    def _check_ruby(self) -> bool:
        r = self._query('query @skip { __typename }')
        if _error_contains(r, "'@skip' can't be applied to queries"):
            return True
        if _error_contains(r, "Directive 'skip' is missing required arguments: if"):
            return True
        r = self._query('query @deprecated { __typename }')
        if _error_contains(r, "'@deprecated' can't be applied to queries"):
            return True
        r = self._query('query { __typename @skip }')
        return _error_contains(r, "Directive 'skip' is missing required arguments: if")

    def _check_hypergraphql(self) -> bool:
        r = self._query('zzz { __typename }')
        if _error_contains(r, 'Validation error of type InvalidSyntax: Invalid query syntax.'):
            return True
        r = self._query('query { alias1:__typename @deprecated }')
        return _error_contains(r, "Validation error of type UnknownDirective: Unknown directive deprecated @ '__typename'")

    def _check_graphqljava(self) -> bool:
        r = self._query('queryy { __typename }')
        if _error_contains(r, "Invalid Syntax : offending token 'queryy'"):
            return True
        r = self._query('query @aaa@aaa { __typename }')
        if _error_contains(r, 'Validation error of type DuplicateDirectiveName'):
            return True
        r = self._query('')
        return _error_contains(r, "Invalid Syntax : offending token '<EOF>'")

    def _check_ariadne(self) -> bool:
        r = self._query('query { __typename @abc }')
        if _error_contains(r, "Unknown directive '@abc'.") and 'data' not in r:
            return True
        r = self._query('')
        return _error_contains(r, 'The query must be a string.')

    def _check_graphqlapiforwp(self) -> bool:
        r = self._query('query @skip { __typename }')
        if _error_contains(r, "Argument 'if' cannot be empty, so directive 'skip' has been ignored"):
            return True
        r = self._query('query @doesnotexist { __typename }')
        if _error_contains(r, "No DirectiveResolver resolves directive with name 'doesnotexist'"):
            return True
        r = self._query('')
        return _error_contains(r, 'The query in the body is empty')

    def _check_wpgraphql(self) -> bool:
        r = self._query('')
        if _error_contains(r, 'GraphQL Request must include at least one of those two parameters: "query" or "queryId"'):
            return True
        r = self._query('query { alias1$1:__typename }')
        if not _error_contains(r, 'Syntax Error: Expected Name, found $'):
            return False
        try:
            debug_msg = r['extensions']['debug'][0]
            if debug_msg.get('type') == 'DEBUG_LOGS_INACTIVE':
                return True
        except (KeyError, IndexError, TypeError):
            pass
        return False

    def _check_gqlgen(self) -> bool:
        r = self._query('query { __typename { }')
        if _error_contains(r, 'expected at least one definition'):
            return True
        r = self._query('query { alias^_:__typename { }')
        return _error_contains(r, 'Expected Name, found <Invalid>')

    def _check_graphqlgo(self) -> bool:
        r = self._query('query { __typename { }')
        if _error_contains(r, 'Unexpected empty IN'):
            return True
        r = self._query('')
        if _error_contains(r, 'Must provide an operation.'):
            return True
        r = self._query('query { __typename }')
        try:
            if r.get('data', {}).get('__typename') == 'RootQuery':
                return True
        except (AttributeError, TypeError):
            pass
        return False

    def _check_juniper(self) -> bool:
        r = self._query('queryy { __typename }')
        if _error_contains(r, 'Unexpected "queryy"'):
            return True
        r = self._query('')
        return _error_contains(r, 'Unexpected end of input')

    def _check_sangria(self) -> bool:
        r = self._query('queryy { __typename }')
        syntax_err = r.get('syntaxError', '')
        return 'Invalid input "queryy"' in syntax_err

    def _check_strawberry(self) -> bool:
        r = self._query('query @deprecated { __typename }')
        return _error_contains(r, "Directive '@deprecated' may not be used on query.") and 'data' in r

    def _check_tartiflette(self) -> bool:
        r = self._query('query @a { __typename }')
        if _error_contains(r, 'Unknow Directive < @a >.'):
            return True
        r = self._query('query @skip { __typename }')
        if _error_contains(r, 'Missing mandatory argument < if > in directive < @skip >.'):
            return True
        r = self._query('query { __typename @deprecated }')
        return _error_contains(r, 'Directive < @deprecated > is not used in a valid location.')

    def _check_dgraph(self) -> bool:
        r = self._query('query { __typename @cascade }')
        if r.get('data', {}).get('__typename', '') == 'Query':
            return True
        r = self._query('query { __typename }')
        return _error_contains(r, "Not resolving __typename. There's no GraphQL schema in Dgraph")

    def _check_graphql_yoga(self) -> bool:
        r = self._query('subscription { __typename }')
        return (
            _error_contains(r, 'asyncExecutionResult[Symbol.asyncIterator] is not a function')
            or _error_contains(r, 'Unexpected error.')
        )

    def _check_lighthouse(self) -> bool:
        r = self._query('query { __typename @include(if: falsee) }')
        return _error_contains(r, 'Internal server error') or _error_contains(r, 'internal', part='category')

    def _check_mercurius(self) -> bool:
        r = self._query('')
        return _error_contains(r, 'Unknown query')

    def _check_directus(self) -> bool:
        r = self._query('')
        errors = r.get('errors', [])
        if errors and isinstance(errors, list) and isinstance(errors[0], dict):
            return errors[0].get('extensions', {}).get('code', '') == 'INVALID_PAYLOAD'
        return False

    def _check_tailcall(self) -> bool:
        r = self._query('aa { __typename }')
        return _error_contains(r, 'expected executable_definition')

    def _check_graphqldotnet(self) -> bool:
        r = self._query('query @skip { __typename }')
        return _error_contains(r, "Directive 'skip' may not be used on Query.")

    def _check_hotchocolate(self) -> bool:
        r = self._query('queryy { __typename }')
        if _error_contains(r, 'Unexpected token: Name.'):
            return True
        r = self._query('query @aaa@aaa { __typename }')
        return _error_contains(r, 'The specified directive `aaa` is not supported by the current schema.')

    def _check_inigo(self) -> bool:
        r = self._query('query { __typename }')
        return 'extensions' in r and 'inigo' in r.get('extensions', {})
