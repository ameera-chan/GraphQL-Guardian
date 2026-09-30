"""Abstract base class for all security scanners."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from src.utils.http_client import HTTPClient
from src.utils.logger import ScannerLogger
from src.utils.evidence import build_evidence, default_rule_id, default_state
from src.reporters.models import Finding
from src.config import DEFAULT_TIMEOUT
from src.risk.rating import rate_finding


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners.
    
    Provides common functionality:
    - HTTP client for GraphQL requests
    - Logging infrastructure
    - Finding creation and management
    - Schema access utilities
    """
    
    def __init__(
        self, 
        endpoint: str, 
        schema: Optional[Dict] = None, 
        config: Optional[Dict] = None,
        graph: Optional[Dict] = None
    ):
        """
        Initialize base scanner.
        
        Args:
            endpoint: GraphQL endpoint URL
            schema: Introspection schema data
            config: Optional configuration (headers, users, etc.)
            graph: Optional dependency graph data
        """
        self.endpoint = endpoint
        self.schema = schema or {}
        self.config = config or {}
        self.graph = graph
        
        # Initialize HTTP client with default headers and optional proxy
        default_headers = self.config.get('headers', {})
        proxy = self.config.get('proxy')
        self.http_client = HTTPClient(
            endpoint, 
            default_headers=default_headers,
            timeout=DEFAULT_TIMEOUT,
            proxy=proxy
        )
        
        # Initialize logger (subclass name will be the logger name)
        self.logger = ScannerLogger(self.__class__.__name__)
        
        # Storage for findings
        self.findings: List[Finding] = []
        
        # Cache type map for easy access
        self._type_map_cache = None
    
    @abstractmethod
    def run(self) -> List[Finding]:
        """
        Run the scanner and return findings.
        
        Must be implemented by subclasses.
        
        Returns:
            List of Finding objects
        """
        pass
    
    def add_finding(
        self, 
        title: str, 
        description: str, 
        severity: str, 
        category: str, 
        **kwargs
    ) -> Finding:
        """
        Create and add a finding to the results.
        
        Args:
            title: Finding title
            description: Detailed description
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            category: Category (CONFIG, DOS, INJECTION, AUTH, AUDIT)
            **kwargs: Additional fields (evidence, remediation, etc.)
            
        Returns:
            The created Finding object
        """
        response = kwargs.pop("response", None)
        request = kwargs.pop("request", None)
        artifacts = kwargs.pop("artifacts", None)
        reproduction = kwargs.pop("reproduction", None)
        rule_id = kwargs.pop("rule_id", None) or default_rule_id(category, title)
        risk = kwargs.pop("risk", None)
        risk_rating = rate_finding(category=category, severity=severity, risk=risk)
        severity = risk_rating["severity"]
        confidence = kwargs.pop("confidence", "high" if response or request else "medium")
        state = kwargs.pop("state", default_state(severity, has_http_evidence=bool(response or request)))
        details = kwargs.pop("evidence", None)

        if response or request or artifacts:
            normalized_evidence = build_evidence(
                rule_id=rule_id,
                confidence=confidence,
                state=state,
                details=details,
                request=request,
                response=response,
                artifacts=artifacts,
                reproduction=reproduction,
            )
            kwargs["evidence"] = normalized_evidence
            reproduction = normalized_evidence.reproduction
        else:
            kwargs["evidence"] = details

        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            category=category,
            endpoint=self.endpoint,
            risk=risk_rating,
            rule_id=rule_id,
            confidence=confidence,
            state=state,
            reproduction=reproduction,
            **kwargs
        )
        self.findings.append(finding)
        return finding
    
    def get_type_map(self) -> Dict:
        """
        Get the schema type map with caching.
        
        Returns:
            Dictionary mapping type names to type definitions
        """
        if self._type_map_cache is None:
            # Handle wrapped schema
            schema = self.schema.get('data', self.schema) if 'data' in self.schema else self.schema
            self._type_map_cache = {t['name']: t for t in schema['__schema']['types']}
        return self._type_map_cache
    
    def get_query_type(self) -> Optional[Dict]:
        """
        Get the Query type definition.
        
        Returns:
            Query type dict or None
        """
        schema = self.schema.get('data', self.schema) if 'data' in self.schema else self.schema
        query_type_ref = schema['__schema'].get('queryType')
        if query_type_ref:
            return self.get_type_map().get(query_type_ref['name'])
        return None
    
    def get_mutation_type(self) -> Optional[Dict]:
        """
        Get the Mutation type definition.
        
        Returns:
            Mutation type dict or None
        """
        schema = self.schema.get('data', self.schema) if 'data' in self.schema else self.schema
        mutation_type_ref = schema['__schema'].get('mutationType')
        if mutation_type_ref:
            return self.get_type_map().get(mutation_type_ref['name'])
        return None
