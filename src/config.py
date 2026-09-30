"""Centralized configuration constants for GraphQL Guardian."""

# HTTP Settings
DEFAULT_TIMEOUT = 10
MAX_RETRIES = 3
RATE_LIMIT_DELAY = 0.5

# DoS Thresholds
DOS_ALIAS_COUNT = 100
DOS_BATCH_SIZE = 10
DOS_DIRECTIVE_COUNT = 100
DOS_FIELD_DUPLICATION_COUNT = 200
DOS_CIRCULAR_DEPTH = 10
DOS_PAGINATION_OVERRIDE_LIMIT = 10000

# Query Complexity
MAX_QUERY_DEPTH = 15
MAX_SELECTION_DEPTH = 3

# Injection Testing
MAX_PAYLOADS_PER_FIELD = 50
INJECTION_TIMEOUT = 5

# Auth Testing
AUTH_TEST_TIMEOUT = 10
MAX_TEST_RESOURCES = 5

# Output Settings
DEFAULT_REPORT_FORMAT = 'json'
REPORT_FORMATS = ['json', 'csv', 'html']

# Severity Levels
SEVERITY_CRITICAL = 'CRITICAL'
SEVERITY_HIGH = 'HIGH'
SEVERITY_MEDIUM = 'MEDIUM'
SEVERITY_LOW = 'LOW'
SEVERITY_INFO = 'INFO'

# Categories
CATEGORY_CONFIG = 'CONFIG'
CATEGORY_DOS = 'DOS'
CATEGORY_INJECTION = 'INJECTION'
CATEGORY_AUTH = 'AUTH'
CATEGORY_AUDIT = 'AUDIT'

# GraphiQL Interface Paths
GRAPHIQL_PATHS = [
    '/graphiql',
    '/graphql',
    '/playground',
    '/explorer',
    '/altair',
    '/voyager',
    '/sandbox',
    '/v1/graphiql',
    '/v1/explorer',
    '/v1/playground',
    '/v1/altair',
    '/v1/voyager',
    '/graphql/playground',
    '/graphql/altair',
    '/graphql/voyager',
]

# ─── Scan Profiles ─────────────────────────────────────────────────────────────
# Each check is tagged with the MINIMUM profile required to run it.
# passive  →  Read-only / safe reconnaissance (no attack traffic)
# default  →  Standard pentest (moderate probes, low crash risk)
# aggressive →  Full attack (destructive DoS, can cause downtime)
PROFILE_PASSIVE = 'passive'
PROFILE_DEFAULT = 'default'
PROFILE_AGGRESSIVE = 'aggressive'

# Ordered list — each level includes all checks from levels below it
PROFILE_LEVELS = [PROFILE_PASSIVE, PROFILE_DEFAULT, PROFILE_AGGRESSIVE]

def profile_allows(current_profile: str, required_profile: str) -> bool:
    """Return True if *current_profile* is >= *required_profile* in depth."""
    return PROFILE_LEVELS.index(current_profile) >= PROFILE_LEVELS.index(required_profile)

# Error Detection Keywords
SQL_ERROR_KEYWORDS = ["syntax error", "sql", "database", "ora-", "mysql", "postgres"]
VERBOSE_ERROR_KEYWORDS = ['stack trace', 'exception', 'traceback', 'internal server error']

# Field Stuffing – common root-level field names to probe when introspection is disabled
FIELD_STUFFING_WORDS = [
    'user', 'users', 'me', 'admin', 'login', 'viewer',
    'account', 'accounts', 'profile', 'node', 'search',
    'config', 'settings', 'flag', 'internal', 'debug',
    'system', 'health', 'secret', 'token', 'session',
]

# Fingerprinting Category
CATEGORY_RECON = 'RECON'

# Common GraphQL Endpoint Paths (for discovery)
# Combined from graphw00f + Black-Hat-GraphQL Ch4 common-graphql-endpoints.txt
GRAPHQL_ENDPOINT_PATHS = [
    '/graphql',
    '/graphiql',
    '/api/graphql',
    '/api/graphiql',
    '/v1/graphql',
    '/v2/graphql',
    '/v3/graphql',
    '/v1/graphiql',
    '/v2/graphiql',
    '/v3/graphiql',
    '/graphql/v1',
    '/graphql/v2',
    '/graphql/v3',
    '/console',
    '/playground',
    '/gql',
    '/query',
    '/index.php?graphql',
    '/rpc/graphql',
    '/explorer',
    '/api/v1/graphql',
    '/api/v2/graphql',
    '/api/v3/graphql',
    '/api/v1/graphiql',
    '/api/v2/graphiql',
    '/api/v3/graphiql',
    '/v1/playground',
    '/v2/playground',
    '/v3/playground',
    '/api/v1/playground',
    '/api/v2/playground',
    '/api/v3/playground',
]

# Common GraphQL WebSocket / subscription endpoints
GRAPHQL_WEBSOCKET_PATHS = [
    '/graphql',
    '/subscriptions',
    '/socket',
    '/socket/graphql',
    '/ws',
    '/ws/graphql',
    '/api/graphql',
    '/api/subscriptions',
]

# Asset reconnaissance limits
ASSET_RECON_MAX_DOCUMENTS = 8
ASSET_RECON_MAX_SCRIPT_FETCHES = 6
