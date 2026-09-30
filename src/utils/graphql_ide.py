"""GraphQL IDE detection helpers."""

from __future__ import annotations

from typing import Optional


IDE_SIGNATURES = {
    "GraphiQL": ("graphiql", "graphiql.min.css", "graphiql explorer"),
    "GraphQL Playground": ("graphql playground", "playground cdn", "graphql-playground"),
    "Apollo Sandbox": ("apollo sandbox", "apollo-server-landing-page", "embeddable-sandbox"),
    "Altair": ("altair", "altair graphql", "altairgraphql"),
    "GraphQL Voyager": ("graphql voyager", "graphql-voyager", "voyager"),
}


def detect_graphql_ide(html: str) -> Optional[str]:
    """Return the GraphQL IDE/tool name detected in an HTML response."""
    content = (html or "").lower()
    for name, signatures in IDE_SIGNATURES.items():
        if any(signature in content for signature in signatures):
            return name
    return None
