"""Centralized HTTP client for GraphQL requests."""

import requests
import json
import time
from typing import Any, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urljoin


@dataclass
class GraphQLResponse:
    """Structured response from a GraphQL request."""
    data: Optional[Dict]
    errors: Optional[list]
    status_code: int
    raw_text: str
    response_time: float
    request_method: Optional[str] = None
    request_url: Optional[str] = None
    request_headers: Optional[Dict[str, str]] = None
    request_body: Optional[Any] = None
    response_headers: Optional[Dict[str, str]] = None
    
    def has_data(self) -> bool:
        """Check if response contains data."""
        return self.data is not None and self.data != {}
    
    def has_errors(self) -> bool:
        """Check if response contains errors."""
        return self.errors is not None and len(self.errors) > 0
    
    def is_success(self) -> bool:
        """Check if request was successful."""
        return self.status_code == 200


class HTTPClient:
    """Centralized HTTP client for GraphQL requests with consistent error handling."""
    
    def __init__(
        self,
        endpoint: str,
        default_headers: Optional[Dict] = None,
        timeout: int = 10,
        proxy: Optional[str] = None
    ):
        """
        Initialize the HTTP client.
        
        Args:
            endpoint: The GraphQL endpoint URL
            default_headers: Default headers to include in requests
            timeout: Request timeout in seconds
            proxy: Optional HTTP(S) proxy URL (e.g. http://127.0.0.1:8080)
        """
        self.endpoint = endpoint
        self.default_headers = default_headers or {'Content-Type': 'application/json'}
        self.timeout = timeout
        self.proxies = {'http': proxy, 'https': proxy} if proxy else None
    
    def post_graphql(
        self, 
        query: str, 
        variables: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> GraphQLResponse:
        """
        Send a GraphQL POST request.
        
        Args:
            query: The GraphQL query string
            variables: Optional query variables
            headers: Optional headers to merge with defaults
            
        Returns:
            GraphQLResponse with structured response data
        """
        merged_headers = {**self.default_headers, **(headers or {})}
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        
        start_time = time.time()
        try:
            response = requests.post(
                self.endpoint,
                json=payload,
                headers=merged_headers,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=not bool(self.proxies)  # Disable SSL verify when using proxy
            )
            elapsed = time.time() - start_time
            
            json_data = response.json() if response.text else {}
            return GraphQLResponse(
                data=json_data.get('data'),
                errors=json_data.get('errors'),
                status_code=response.status_code,
                raw_text=response.text,
                response_time=elapsed,
                request_method='POST',
                request_url=self.endpoint,
                request_headers=merged_headers,
                request_body=payload,
                response_headers=dict(response.headers),
            )
        except requests.exceptions.RequestException as e:
            elapsed = time.time() - start_time
            return GraphQLResponse(
                data=None,
                errors=[{'message': str(e)}],
                status_code=0,
                raw_text='',
                response_time=elapsed,
                request_method='POST',
                request_url=self.endpoint,
                request_headers=merged_headers,
                request_body=payload,
            )
        except json.JSONDecodeError:
            elapsed = time.time() - start_time
            return GraphQLResponse(
                data=None,
                errors=[{'message': 'Invalid JSON response'}],
                status_code=response.status_code if 'response' in locals() else 0,
                raw_text=response.text if 'response' in locals() else '',
                response_time=elapsed,
                request_method='POST',
                request_url=self.endpoint,
                request_headers=merged_headers,
                request_body=payload,
                response_headers=dict(response.headers) if 'response' in locals() else None,
            )
    
    def post_batch(self, queries: list) -> list:
        """
        Send a batch of GraphQL queries.
        
        Args:
            queries: List of query dictionaries
            
        Returns:
            Response from batch request
        """
        try:
            response = requests.post(
                self.endpoint,
                json=queries,
                headers=self.default_headers,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=not bool(self.proxies)
            )
            return response
        except requests.exceptions.RequestException:
            return None
    
    def get(self, path: str = '', headers: Optional[Dict] = None) -> Optional[requests.Response]:
        """
        Send a GET request (for checking GraphiQL interfaces).
        
        Args:
            path: Path to append to base endpoint
            headers: Optional headers to merge with defaults
            
        Returns:
            Response object or None on error
        """
        url = urljoin(self.endpoint, path)
        merged_headers = {**self.default_headers, **(headers or {})}
        
        try:
            return requests.get(
                url,
                headers=merged_headers,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=not bool(self.proxies)
            )
        except requests.exceptions.RequestException:
            return None

    def get_graphql(self, query: str, headers: Optional[Dict] = None) -> GraphQLResponse:
        """
        Send a GraphQL GET request (query as URL parameter).

        Args:
            query: The GraphQL query string
            headers: Optional headers to merge with defaults

        Returns:
            GraphQLResponse with structured response data
        """
        merged_headers = {**self.default_headers, **(headers or {})}
        start_time = time.time()
        try:
            response = requests.get(
                self.endpoint,
                params={'query': query},
                headers=merged_headers,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=not bool(self.proxies)
            )
            elapsed = time.time() - start_time
            json_data = response.json() if response.text else {}
            return GraphQLResponse(
                data=json_data.get('data'),
                errors=json_data.get('errors'),
                status_code=response.status_code,
                raw_text=response.text,
                response_time=elapsed,
                request_method='GET',
                request_url=response.url,
                request_headers=merged_headers,
                request_body=None,
                response_headers=dict(response.headers),
            )
        except requests.exceptions.RequestException as e:
            elapsed = time.time() - start_time
            return GraphQLResponse(
                data=None,
                errors=[{'message': str(e)}],
                status_code=0,
                raw_text='',
                response_time=elapsed,
                request_method='GET',
                request_url=self.endpoint,
                request_headers=merged_headers,
                request_body=None,
            )
        except json.JSONDecodeError:
            elapsed = time.time() - start_time
            return GraphQLResponse(
                data=None,
                errors=[{'message': 'Invalid JSON response'}],
                status_code=response.status_code if 'response' in locals() else 0,
                raw_text=response.text if 'response' in locals() else '',
                response_time=elapsed,
                request_method='GET',
                request_url=response.url if 'response' in locals() else self.endpoint,
                request_headers=merged_headers,
                request_body=None,
                response_headers=dict(response.headers) if 'response' in locals() else None,
            )
