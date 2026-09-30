from src.scanner.asset_recon import AssetReconScanner


class _Response:
    def __init__(self, url, text, content_type="text/html"):
        self.url = url
        self.text = text
        self.status_code = 200
        self.headers = {"content-type": content_type}


def test_asset_recon_mines_client_documents(monkeypatch):
    root_html = """
    <html>
      <script src="/static/app.js"></script>
      <a href="/graphql">GraphQL</a>
    </html>
    """
    app_js = """
    const endpoint = "/graphql";
    const wsEndpoint = "ws://target.local/subscriptions";
    const authHeader = "Authorization";
    const op = `query AdminOverview { users { id email } }`;
    const mutation = `mutation UpdateUser { updateUser(id: "1") { id } }`;
    const persisted = { extensions: { persistedQuery: { sha256Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } } };
    const env = "https://staging.target.local/graphql";
    """

    responses = {
        "http://target.local/": _Response("http://target.local/", root_html, "text/html"),
        "http://target.local/graphql": _Response("http://target.local/graphql", root_html, "text/html"),
        "http://target.local/static/app.js": _Response("http://target.local/static/app.js", app_js, "application/javascript"),
    }

    def fake_get(url, **kwargs):
        return responses[url]

    monkeypatch.setattr("src.scanner.asset_recon.requests.get", fake_get)

    scanner = AssetReconScanner("http://target.local/graphql")
    findings = scanner.run()

    assert scanner.report["summary"]["documents_scanned"] == 3
    assert scanner.report["summary"]["graphql_endpoints"] >= 2
    assert scanner.report["summary"]["subscription_endpoints"] == 1
    assert scanner.report["summary"]["operations"] == 2
    assert scanner.report["summary"]["persisted_query_hashes"] == 1
    assert scanner.report["summary"]["auth_headers"] == 1
    titles = {finding.title for finding in findings}
    assert "Client Assets Leak GraphQL Endpoints" in titles
    assert "Client Assets Expose Named GraphQL Operations" in titles
