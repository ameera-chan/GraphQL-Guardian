"""Blind schema reconstruction when introspection is disabled.

Inspired by Clairvoyance (https://github.com/nikitastupin/clairvoyance).
Uses wordlist-driven field probing + GraphQL error-message regex mining
to progressively rebuild the schema without introspection access.
"""

import re
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

from src.utils.http_client import HTTPClient
from src.utils.logger import ScannerLogger

# ── Error-message regex patterns (derived from Clairvoyance) ────────────────

_NAME = r"""[_0-9A-Za-z\.\[\]!]+"""

# Patterns for extracting valid fields from "Did you mean ..." suggestions
FIELD_SUGGESTION_SINGLE = re.compile(
    r"""Cannot query field ['"][_0-9A-Za-z]+['"] on type ['"]""" + _NAME +
    r"""['"]\. Did you mean ['"](?P<field>""" + _NAME + r""")['"]\?"""
)
FIELD_SUGGESTION_DOUBLE = re.compile(
    r"""Cannot query field ['"][_0-9A-Za-z]+['"] on type ['"]""" + _NAME +
    r"""['"]\. Did you mean ['"](?P<one>""" + _NAME + r""")['"] or ['"](?P<two>""" + _NAME + r""")['"]\?"""
)
FIELD_SUGGESTION_MULTI = re.compile(
    r"""Cannot query field ['"][_0-9A-Za-z]+['"] on type ['"]""" + _NAME +
    r"""['"]\. Did you mean (?P<multi>(['"]""" + _NAME + r"""['"],? )+)"""
    r"""(?:or ['"](?P<last>""" + _NAME + r""")['"])?\?"""
)

# Patterns for detecting valid fields that need sub-selection
FIELD_NEEDS_SELECTION = re.compile(
    r"""Field ['"](?P<field>""" + _NAME + r""")['"] of type ['"](?P<typeref>""" + _NAME +
    r""")['"] must have a (?:selection of subfields|sub selection)\."""
)

# Pattern to extract the typename for a context
TYPENAME_REGEX = re.compile(
    r"""Cannot query field ['"][_0-9A-Za-z]+['"] on type ['"](?P<typename>""" + _NAME + r""")['"]"""
)

# Patterns for argument discovery
ARG_SUGGESTION_SINGLE = re.compile(
    r"""Unknown argument ['"][_0-9A-Za-z]+['"] on field ['"]""" + _NAME +
    r"""['"](?:\s+of type ['"]""" + _NAME + r"""['"])?\. Did you mean ['"](?P<arg>""" + _NAME + r""")['"]\?"""
)
ARG_SUGGESTION_DOUBLE = re.compile(
    r"""Unknown argument ['"][_0-9A-Za-z]+['"] on field ['"]""" + _NAME +
    r"""['"](?:\s+of type ['"]""" + _NAME +
    r"""['"])?\. Did you mean ['"](?P<first>""" + _NAME + r""")['"] or ['"](?P<second>""" + _NAME + r""")['"]\?"""
)

# Pattern for type reference extraction from required-arg errors
TYPEREF_REGEX = re.compile(
    r"""Field ['"]""" + _NAME + r"""['"] argument ['"]""" + _NAME +
    r"""['"] of type ['"](?P<typeref>""" + _NAME + r""")['"] is required"""
)


def _load_default_wordlist() -> List[str]:
    """Load the bundled GraphQL wordlist."""
    wl_path = Path(__file__).resolve().parent.parent.parent / "wordlists" / "graphql_fields.txt"
    if not wl_path.exists():
        wl_path = Path("/usr/share/guardql/wordlists/graphql_fields.txt")
    if not wl_path.exists():
        return []
    with open(wl_path, "r", encoding="utf-8") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


def _extract_suggestions(error_msg: str) -> Set[str]:
    """Extract field/arg suggestions from a single error message."""
    suggestions: Set[str] = set()

    # Check single suggestion
    m = FIELD_SUGGESTION_SINGLE.search(error_msg)
    if m:
        suggestions.add(m.group("field"))
        return suggestions

    # Check double suggestion
    m = FIELD_SUGGESTION_DOUBLE.search(error_msg)
    if m:
        suggestions.add(m.group("one"))
        suggestions.add(m.group("two"))
        return suggestions

    # Check multi suggestion
    m = FIELD_SUGGESTION_MULTI.search(error_msg)
    if m:
        for part in m.group("multi").split(","):
            cleaned = part.strip().strip("'\" ")
            if cleaned:
                suggestions.add(cleaned)
        if m.group("last"):
            suggestions.add(m.group("last"))
        return suggestions

    return suggestions


def _extract_needs_selection(error_msg: str) -> Optional[Tuple[str, str]]:
    """If field needs sub-selection, return (field_name, type_ref)."""
    m = FIELD_NEEDS_SELECTION.search(error_msg)
    if m:
        return m.group("field"), m.group("typeref")
    return None


def _clean_typeref(raw: str) -> str:
    """Strip list/non-null decorators from a type reference string."""
    return raw.replace("!", "").replace("[", "").replace("]", "").strip()


def _extract_arg_suggestions(error_msg: str) -> Set[str]:
    """Extract argument suggestions from error messages."""
    suggestions: Set[str] = set()

    m = ARG_SUGGESTION_SINGLE.search(error_msg)
    if m:
        suggestions.add(m.group("arg"))
        return suggestions

    m = ARG_SUGGESTION_DOUBLE.search(error_msg)
    if m:
        suggestions.add(m.group("first"))
        suggestions.add(m.group("second"))
        return suggestions

    return suggestions


class BlindIntrospector:
    """Reconstructs a GraphQL schema without introspection access.

    Algorithm (Clairvoyance-inspired):
    1. Send batches of wordlist items as fields in a query.
    2. Parse error messages to collect valid field names + suggestions.
    3. For each valid field, probe its type (scalar vs object).
    4. For object fields, recurse one level to discover sub-fields.
    5. Probe arguments for each field.
    6. Build a JSON schema representation of discovered types.
    """

    def __init__(
        self,
        endpoint: str,
        wordlist: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        bucket_size: int = 10,
        max_depth: int = 2,
    ):
        self.endpoint = endpoint
        self.wordlist = wordlist or _load_default_wordlist()
        self.bucket_size = bucket_size
        self.max_depth = max_depth
        self.logger = ScannerLogger("BlindIntrospector")

        self.http_client = HTTPClient(
            endpoint,
            default_headers=headers or {"Content-Type": "application/json"},
            proxy=proxy,
        )

        # Discovered schema structures
        self.discovered_fields: Dict[str, Dict[str, Any]] = {}  # typename -> {field: info}
        self.discovered_types: Dict[str, str] = {}               # typename -> kind
        self.discovered_args: Dict[str, List[str]] = {}          # typename.field -> [arg names]
        self.root_typename: Optional[str] = None
        self.mutation_typename: Optional[str] = None

        # Stats
        self.requests_sent = 0
        self.start_time = 0.0

    # ── Public API ───────────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        """Run blind introspection and return a schema dict.

        Returns:
            Dict with discovered schema in introspection-compatible JSON format.
        """
        self.start_time = time.time()
        self.logger.info(f"Starting blind introspection on {self.endpoint}")
        self.logger.info(f"Wordlist: {len(self.wordlist)} words, bucket size: {self.bucket_size}")

        # Step 1: Detect root typename
        self.root_typename = self._detect_root_typename("query")
        self.logger.info(f"Root query typename: {self.root_typename or 'Unknown'}")

        # Also try mutation typename
        self.mutation_typename = self._detect_root_typename("mutation")
        if self.mutation_typename:
            self.logger.info(f"Root mutation typename: {self.mutation_typename}")

        # Step 2: Probe fields on root query type
        if self.root_typename:
            self._probe_fields_for_type(self.root_typename, "query", depth=0)

        # Step 3: Probe fields on mutation type
        if self.mutation_typename:
            self._probe_fields_for_type(self.mutation_typename, "mutation", depth=0)

        elapsed = time.time() - self.start_time
        self.logger.info(
            f"Blind introspection complete: {len(self.discovered_fields)} type(s), "
            f"{self.requests_sent} requests in {elapsed:.1f}s"
        )

        return self._build_schema_json()

    # ── Root typename detection ──────────────────────────────────────────────

    def _detect_root_typename(self, operation: str = "query") -> Optional[str]:
        """Detect the root typename by sending a bogus field."""
        query = f'{operation} {{ __IAmABogusField }}'
        response = self.http_client.post_graphql(query)
        self.requests_sent += 1

        if response.has_errors():
            for error in response.errors:
                msg = error.get("message", "") if isinstance(error, dict) else str(error)
                m = TYPENAME_REGEX.search(msg)
                if m:
                    name = _clean_typeref(m.group("typename"))
                    return name
        return None

    # ── Field probing ────────────────────────────────────────────────────────

    def _probe_fields_for_type(
        self,
        typename: str,
        operation: str,
        depth: int,
        parent_path: str = "",
    ) -> None:
        """Probe all wordlist items as fields on a given type."""
        if depth > self.max_depth:
            return

        if typename in self.discovered_fields:
            return  # already explored

        self.discovered_fields[typename] = {}
        self.discovered_types[typename] = "OBJECT"

        valid_fields: Set[str] = set()
        object_fields: Dict[str, str] = {}  # field_name -> typeref

        # Send words in buckets
        for i in range(0, len(self.wordlist), self.bucket_size):
            bucket = self.wordlist[i : i + self.bucket_size]

            # Build the query with all bucket fields (each gets a dummy sub-selection)
            fields_str = " ".join(bucket)
            if parent_path:
                inner = f"{parent_path} {{ {fields_str} }}"
            else:
                inner = fields_str

            query = f"{operation} {{ {inner} }}"
            response = self.http_client.post_graphql(query)
            self.requests_sent += 1

            if not response.has_errors():
                # All fields accepted — mark them as valid
                valid_fields.update(bucket)
                continue

            # Track which fields were explicitly rejected
            rejected: Set[str] = set()
            for error in response.errors:
                msg = error.get("message", "") if isinstance(error, dict) else str(error)

                # Check if a field was rejected
                reject_match = re.search(
                    r"""Cannot query field ['"](?P<field>[_A-Za-z][_0-9A-Za-z]*)['"]""",
                    msg,
                )
                if reject_match:
                    rejected.add(reject_match.group("field"))

                # Collect suggestions from the error
                suggestions = _extract_suggestions(msg)
                valid_fields.update(suggestions)

                # Check if field needs sub-selection (it's an object type)
                sel_info = _extract_needs_selection(msg)
                if sel_info:
                    fname, tref = sel_info
                    valid_fields.add(fname)
                    object_fields[fname] = _clean_typeref(tref)

            # Fields not rejected are potentially valid
            for word in bucket:
                if word not in rejected:
                    valid_fields.add(word)

        # Remove any obvious false positives (GraphQL builtins that look valid)
        valid_fields -= {"__typename", "__schema", "__type"}

        self.logger.info(f"  [{typename}] Discovered {len(valid_fields)} field(s)")

        # Step 3: For each valid field, determine its type
        for field_name in sorted(valid_fields):
            field_info = self._probe_single_field(field_name, typename, operation, parent_path)
            if field_info:
                self.discovered_fields[typename][field_name] = field_info

                # Probe arguments
                args = self._probe_field_args(field_name, operation, parent_path)
                if args:
                    key = f"{typename}.{field_name}"
                    self.discovered_args[key] = list(args)

        # Step 4: Recurse into object-typed fields
        for field_name, type_ref in object_fields.items():
            clean_ref = _clean_typeref(type_ref)
            if clean_ref and clean_ref not in self.discovered_fields and not clean_ref.startswith("__"):
                new_parent = f"{parent_path} {{ {field_name}" if parent_path else field_name
                self._probe_fields_for_type(clean_ref, operation, depth + 1, new_parent)

    def _probe_single_field(
        self,
        field_name: str,
        typename: str,
        operation: str,
        parent_path: str,
    ) -> Optional[Dict[str, Any]]:
        """Probe a single field to determine its type (scalar vs object)."""
        # Try without sub-selection first (works for scalars)
        if parent_path:
            inner = f"{parent_path} {{ {field_name} }}"
        else:
            inner = field_name

        query = f"{operation} {{ {inner} }}"
        response = self.http_client.post_graphql(query)
        self.requests_sent += 1

        type_ref = "String"  # default assumption
        kind = "SCALAR"

        if response.has_errors():
            for error in response.errors:
                msg = error.get("message", "") if isinstance(error, dict) else str(error)

                # Check if it needs sub-selection → it's an object type
                sel_info = _extract_needs_selection(msg)
                if sel_info:
                    _, raw_ref = sel_info
                    type_ref = _clean_typeref(raw_ref)
                    kind = "OBJECT"
                    break

                # Check for type info in required-arg errors
                m = TYPEREF_REGEX.search(msg)
                if m:
                    type_ref = _clean_typeref(m.group("typeref"))
                    break

        elif response.has_data():
            # Field resolved successfully – it's a valid scalar
            pass

        return {"type": type_ref, "kind": kind}

    # ── Argument probing ─────────────────────────────────────────────────────

    def _probe_field_args(
        self,
        field_name: str,
        operation: str,
        parent_path: str,
    ) -> Set[str]:
        """Probe for valid arguments on a field using wordlist + error suggestions."""
        discovered_args: Set[str] = set()

        # Send small batches of argument candidates
        arg_candidates = [w for w in self.wordlist if len(w) < 30][:100]  # Cap for speed
        for i in range(0, len(arg_candidates), self.bucket_size):
            bucket = arg_candidates[i : i + self.bucket_size]
            args_str = ", ".join(f'{w}: "test"' for w in bucket)

            if parent_path:
                inner = f"{parent_path} {{ {field_name}({args_str}) }}"
            else:
                inner = f"{field_name}({args_str})"

            query = f"{operation} {{ {inner} }}"
            response = self.http_client.post_graphql(query)
            self.requests_sent += 1

            if not response.has_errors():
                discovered_args.update(bucket)
                continue

            rejected: Set[str] = set()
            for error in response.errors:
                msg = error.get("message", "") if isinstance(error, dict) else str(error)

                # Check for rejected args
                reject_match = re.search(
                    r"""Unknown argument ['"](?P<arg>[_A-Za-z][_0-9A-Za-z]*)['"]""",
                    msg,
                )
                if reject_match:
                    rejected.add(reject_match.group("arg"))

                # Collect arg suggestions
                suggestions = _extract_arg_suggestions(msg)
                discovered_args.update(suggestions)

            for word in bucket:
                if word not in rejected:
                    discovered_args.add(word)

        return discovered_args

    # ── Schema JSON builder ──────────────────────────────────────────────────

    def _build_schema_json(self) -> Dict[str, Any]:
        """Build an introspection-compatible JSON schema from discovered data."""
        types_list = []

        for typename, fields in self.discovered_fields.items():
            field_defs = []
            for fname, finfo in fields.items():
                arg_defs = []
                arg_key = f"{typename}.{fname}"
                if arg_key in self.discovered_args:
                    for arg_name in self.discovered_args[arg_key]:
                        arg_defs.append({
                            "name": arg_name,
                            "description": None,
                            "defaultValue": None,
                            "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                        })

                field_defs.append({
                    "name": fname,
                    "description": None,
                    "args": arg_defs,
                    "type": {
                        "kind": finfo.get("kind", "SCALAR"),
                        "name": finfo.get("type", "String"),
                        "ofType": None,
                    },
                    "isDeprecated": False,
                    "deprecationReason": None,
                })

            types_list.append({
                "kind": "OBJECT",
                "name": typename,
                "description": None,
                "fields": field_defs,
                "inputFields": None,
                "interfaces": [],
                "enumValues": None,
                "possibleTypes": None,
            })

        schema = {
            "data": {
                "__schema": {
                    "queryType": {"name": self.root_typename} if self.root_typename else None,
                    "mutationType": {"name": self.mutation_typename} if self.mutation_typename else None,
                    "subscriptionType": None,
                    "types": types_list,
                    "directives": [],
                }
            }
        }

        return schema

    # ── Summary ──────────────────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        """Return a summary of what was discovered."""
        total_fields = sum(len(f) for f in self.discovered_fields.values())
        total_args = sum(len(a) for a in self.discovered_args.values())

        return {
            "types_discovered": len(self.discovered_fields),
            "fields_discovered": total_fields,
            "arguments_discovered": total_args,
            "root_query_type": self.root_typename,
            "mutation_type": self.mutation_typename,
            "requests_sent": self.requests_sent,
            "elapsed_seconds": round(time.time() - self.start_time, 1) if self.start_time else 0,
            "types": {
                tname: list(fields.keys())
                for tname, fields in self.discovered_fields.items()
            },
        }
