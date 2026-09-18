"""FastAPI 端到端测试：TestClient 模拟真实 HTTP。"""

import sys
sys.path.insert(0, ".")
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
ok = True

def check(name, cond, extra=""):
    global ok
    print(("PASS" if cond else "FAIL"), name, extra)
    if not cond:
        ok = False

# health / root
check("health", client.get("/health").json() == {"status": "ok"})
check("root", client.get("/").status_code == 200)

# 正常请求：/7 跨 10/11 边界，此时只有 10/8 被覆盖 -> partial
payload = {"rules": [
    {"action": "allow", "cidr": "10.0.0.0/8"},               # full
    {"action": "deny",  "cidr": "10.0.0.0/24"},              # shadowed
    {"action": "deny",  "cidr": "10.0.0.0/7"},               # partial：10/8 已覆盖，新增 11/8
    {"action": "allow", "cidr": "192.168.0.0/16"},           # full
]}
r = client.post("/analyze", json=payload)
check("analyze 200", r.status_code == 200, r.status_code)
data = r.json()
sts = [x["status"] for x in data["results"]]
check("statuses", sts == ["full", "shadowed", "partial", "full"], sts)
partial = data["results"][2]
check("partial effective_cidrs", partial["effective_cidrs"] == ["11.0.0.0/8"], partial)
check("partial covered", partial["covered_addresses"] == 2**24)
s = data["summary"]
check("summary", s == {
    "total_rules": 4, "full_rules": 2, "partial_rules": 1, "shadowed_rules": 1,
    "allow_effective_addresses": 2**24 + 2**16,
    "deny_effective_addresses": 2**24,
}, s)

# 422 用例
def expect_422(name, payload):
    r = client.post("/analyze", json=payload)
    check(name, r.status_code == 422, (r.status_code, r.text[:120]))

expect_422("empty rules", {"rules": []})
expect_422("missing rules body", {})
expect_422("bad cidr host bits", {"rules": [{"action": "allow", "cidr": "10.0.0.1/24"}]})
expect_422("bad prefix /33", {"rules": [{"action": "allow", "cidr": "10.0.0.0/33"}]})
expect_422("garbage cidr", {"rules": [{"action": "allow", "cidr": "not-a-cidr"}]})
expect_422("ipv6 v6 addr", {"rules": [{"action": "allow", "cidr": "2001:db8::/32"}]})
expect_422("ipv6 ::1", {"rules": [{"action": "deny", "cidr": "::1"}]})
expect_422("bad action", {"rules": [{"action": "permit", "cidr": "10.0.0.0/8"}]})
expect_422("missing field", {"rules": [{"cidr": "10.0.0.0/8"}]})
expect_422("empty cidr", {"rules": [{"action": "allow", "cidr": ""}]})
expect_422("octet out of range", {"rules": [{"action": "allow", "cidr": "256.0.0.0/8"}]})

r = client.post("/analyze", data="not-json", headers={"content-type": "application/json"})
check("malformed json -> 422", r.status_code == 422, r.status_code)

# 裸 IP 隐式 /32 合法
r = client.post("/analyze", json={"rules": [{"action": "allow", "cidr": "10.0.0.1"}]})
check("bare /32", r.status_code == 200 and r.json()["results"][0]["cidr"] == "10.0.0.1/32")

# 0.0.0.0/0
r = client.post("/analyze", json={"rules": [
    {"action": "deny", "cidr": "0.0.0.0/0"},
    {"action": "allow", "cidr": "0.0.0.0/0"},
]})
d = r.json()
check("whole internet shadow", [x["status"] for x in d["results"]] == ["full", "shadowed"])
check("whole internet counts", d["summary"]["deny_effective_addresses"] == 2**32
      and d["summary"]["allow_effective_addresses"] == 0)

# OpenAPI 可用
check("openapi", client.get("/openapi.json").status_code == 200)

print("\n" + ("ALL PASS" if ok else "SOME FAILED"))
sys.exit(0 if ok else 1)
