from src.utils.graphql_ide import detect_graphql_ide


def test_detect_graphql_ide_signatures():
    assert detect_graphql_ide("<html>GraphiQL Explorer</html>") == "GraphiQL"
    assert detect_graphql_ide("<html>Apollo Sandbox</html>") == "Apollo Sandbox"
    assert detect_graphql_ide("<html>graphql-voyager</html>") == "GraphQL Voyager"
