import pytest
from src.payloads.matcher import select_payloads
from src.payloads.payload_db import PAYLOADS

def test_xss_selection():
    # Should select XSS payloads for String type with "comment" in name
    payloads = select_payloads("userComment", "String")
    assert any("<script>" in p for p in payloads)
    assert PAYLOADS["XSS"][0] in payloads

def test_sqli_selection_id():
    # Should select SQLi payloads for ID type with "id" in name
    payloads = select_payloads("userId", "ID")
    assert any("OR '1'='1" in p for p in payloads)
    
def test_sqli_selection_int():
    # Should select SQLi payloads for Int type with "limit" (maybe not in keywords?) 
    # Let's check keywords: "id", "user", "name", "search", "filter", "query", "key", "uuid"
    # "limit" is not in keywords. So it should fall back to Generic.
    payloads = select_payloads("limit", "Int")
    # Generic has {{7*7}}
    assert any("{{" in p for p in payloads)
    # Should NOT have XSS
    assert not any("<script>" in p for p in payloads)

def test_ssrf_selection():
    payloads = select_payloads("webhookUrl", "String")
    assert any("localhost" in p for p in payloads)

def test_path_traversal_selection():
    payloads = select_payloads("filePath", "String")
    assert any("etc/passwd" in p for p in payloads)

def test_mixed_keywords():
    # "searchQuery" -> matches SQLi (query)
    payloads = select_payloads("searchQuery", "String")
    assert any("UNION SELECT" in p for p in payloads)

def test_limit_payloads():
    payloads = select_payloads("userId", "ID", limit=2)
    assert len(payloads) == 2

def test_unknown_type():
    # Unknown type should return empty list or maybe generic if we mapped it?
    # Our mapping only has String, Int, Float, ID.
    # If we pass "Boolean", it shouldn't match anything in current DB.
    payloads = select_payloads("isActive", "Boolean")
    assert len(payloads) == 0
