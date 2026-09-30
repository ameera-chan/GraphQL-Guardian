from src.scanner.subscription_tester import SubscriptionSecurityScanner


def test_subscription_scanner_flags_unauthenticated_ack_and_origin_risk():
    schema = {
        "__schema": {
            "subscriptionType": {"name": "Subscription"},
            "types": [
                {
                    "name": "Subscription",
                    "fields": [{"name": "pasteCreated"}],
                }
            ],
        }
    }

    scanner = SubscriptionSecurityScanner(
        "http://localhost:5013/graphql",
        schema=schema,
        asset_recon={"subscription_endpoints": [{"url": "ws://localhost:5013/subscriptions"}]},
    )

    def fake_upgrade(url, origin):
        return {"accepted": True, "status_code": 101, "headers": {}, "error": None}

    def fake_protocol(url, origin):
        return {
            "connected": True,
            "ack": True,
            "message_types": ["connection_ack"],
            "message_sample": ['{"type":"connection_ack"}'],
            "subprotocol": "graphql-transport-ws",
            "error": None,
        }

    scanner._http_upgrade_probe = fake_upgrade
    scanner._graphql_ws_probe = fake_protocol

    findings = scanner.run()

    titles = {finding.title for finding in findings}
    assert "GraphQL WebSocket Endpoint Active" in titles
    assert "Unauthenticated GraphQL WebSocket Handshake Accepted" in titles
    assert "WebSocket Origin Validation Missing" in titles
    assert scanner.report["summary"]["active_endpoints"] >= 1
    assert scanner.report["summary"]["unauthenticated_acks"] >= 1
    assert scanner.report["summary"]["evil_origin_accepted"] >= 1

def test_subscription_scanner_treats_upgrade_without_ack_as_unauthenticated_handshake():
    scanner = SubscriptionSecurityScanner(
        "http://localhost:8090/graphql",
        schema={"__schema": {"subscriptionType": None, "types": []}},
    )

    def fake_upgrade(url, origin):
        return {
            "accepted": origin == scanner.safe_origin,
            "status_code": 101 if origin == scanner.safe_origin else 403,
            "headers": {},
            "error": None,
        }

    def fake_protocol(url, origin):
        return {
            "connected": False,
            "ack": False,
            "message_types": [],
            "message_sample": [],
            "subprotocol": None,
            "error": None,
        }

    scanner._http_upgrade_probe = fake_upgrade
    scanner._graphql_ws_probe = fake_protocol

    findings = scanner.run()
    rule_ids = {item.rule_id for item in findings}

    assert "GG-RECON-UNAUTHENTICATED-GRAPHQL-WS" in rule_ids
    assert scanner.report["summary"]["unauthenticated_handshakes"] >= 1
    assert scanner.report["summary"]["unauthenticated_acks"] == 0

