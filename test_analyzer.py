"""核心算法验证：直接 import analyzer，不依赖 fastapi。"""

import sys, ipaddress
sys.path.insert(0, ".")
from app.analyzer import analyze_rules, parse_ipv4_network, InvalidCIDRError, range_to_cidrs

ok = True
def check(name, cond, extra=""):
    global ok
    print(("PASS" if cond else "FAIL"), name, extra)
    if not cond:
        ok = False

# 1) 基本分类：full / partial / shadowed
res, summ = analyze_rules([
    ("allow", "10.0.0.0/8"),
    ("deny",  "10.1.0.0/16"),       # 被前者完全覆盖 -> shadowed
    ("allow", "10.0.0.0/24"),       # 同样完全覆盖 -> shadowed
    ("deny",  "192.168.0.0/16"),    # 全新 -> full
    ("deny",  "192.168.128.0/17"),  # 与 /16 前半重叠 -> partial，剩 192.168.128.0/17? 不，/16 已含全部
])
statuses = [r.status for r in res]
check("basic statuses", statuses == ["full", "shadowed", "shadowed", "full", "shadowed"], statuses)

# 2) 部分遮蔽且剩余可压缩
res, _ = analyze_rules([
    ("allow", "10.0.0.0/24"),
    ("deny",  "10.0.0.128/25"),     # shadowed
    ("deny",  "10.0.1.0/24"),       # full
])
# 真正的 partial：已覆盖 /24，再给跨边界的 /23
res, _ = analyze_rules([
    ("allow", "10.0.0.0/24"),
    ("deny",  "10.0.0.0/23"),       # 覆盖 10.0.0.0/24 + 10.0.1.0/24，剩 /24
])
check("partial remainder", res[1].status == "partial" and res[1].effective_cidrs == ["10.0.1.0/24"],
      res[1].effective_cidrs)
check("partial covered count", res[1].covered_addresses == 256, res[1].covered_addresses)

# 3) 中间挖洞：/24 之后 /32 与两端合并顺序
res, _ = analyze_rules([
    ("deny", "192.0.2.0/24"),
    ("allow", "192.0.2.10/32"),     # shadowed
])
check("inner /32 shadowed", res[1].status == "shadowed")

# 4) 剩余集合无损 & 最少 CIDR：/24 减去两个 /26
res, _ = analyze_rules([
    ("allow", "10.1.0.0/26"),
    ("allow", "10.1.0.128/26"),
    ("deny",  "10.1.0.0/24"),       # 剩 10.1.0.64/26 + 10.1.0.192/26
])
check("two holes", res[2].status == "partial" and
      res[2].effective_cidrs == ["10.1.0.64/26", "10.1.0.192/26"], res[2].effective_cidrs)

# 5) 相邻区间合并后可压缩：/25 + /25 -> 覆盖后再给 /24
res, _ = analyze_rules([
    ("allow", "172.16.0.0/25"),
    ("allow", "172.16.0.128/25"),
    ("deny",  "172.16.0.0/24"),
])
check("adjacent merge", res[2].status == "shadowed")

# 6) 汇总计数
res, summ = analyze_rules([
    ("allow", "10.0.0.0/8"),          # full: 2^24
    ("deny",  "10.0.0.0/24"),         # shadowed: 0
    ("allow", "10.0.0.0/23"),         # partial: 剩 10.0.2.0/23 ... 等等验证
])
# /8 覆盖 10.0.0.0-10.255.255.255，/23 完全在内 -> shadowed，改一个跨边界用例
res, summ = analyze_rules([
    ("allow", "10.0.0.0/8"),                       # allow 2^24
    ("deny",  "10.0.0.0/24"),                      # shadowed 0
    ("deny",  "11.0.0.0/8"),                       # full deny 2^24
    ("allow", "10.0.0.0/9"),                       # /9 含 10.0..10.127 全在内 -> shadowed 0
])
check("summary allow", summ.allow_effective_addresses == 2**24, summ.allow_effective_addresses)
check("summary deny", summ.deny_effective_addresses == 2**24, summ.deny_effective_addresses)
check("summary counts", (summ.full_rules, summ.partial_rules, summ.shadowed_rules) == (2, 0, 2))

# 7) 0.0.0.0/0 边界 + 最大计数
res, summ = analyze_rules([("deny", "0.0.0.0/0")])
check("whole internet", res[0].status == "full" and summ.deny_effective_addresses == 2**32)

# 8) range_to_cidrs 最少性：随机区间与暴力反解一致
import random
random.seed(42)
for _ in range(300):
    a = random.randint(0, MAX := (1 << 32) - 1)
    b = random.randint(a, MAX)
    cidrs = range_to_cidrs(a, b)
    total = sum(ipaddress.ip_network(c).num_addresses for c in cidrs)
    lo = int(ipaddress.ip_network(cidrs[0]).network_address)
    hi = int(ipaddress.ip_network(cidrs[-1]).broadcast_address)
    assert total == b - a + 1 and lo == a and hi == b, (a, b, cidrs)
    # 相邻 CIDR 不可合并（最少性）：相邻且同前缀的两块只有在“兄弟块”
    # （第一块起点按 2 倍块长对齐）时才能合并成父块。
    nets = [ipaddress.ip_network(c) for c in cidrs]
    for x, y in zip(nets, nets[1:]):
        siblings = int(x.network_address) % (2 * x.num_addresses) == 0
        assert not (int(y.network_address) == int(x.broadcast_address) + 1
                    and x.prefixlen == y.prefixlen and siblings), (a, b, cidrs)
print("PASS range_to_cidrs fuzz (300 intervals, lossless + minimal)")

# 9) 非法输入
for bad in ["10.0.0.1/24", "10.0.0.0/33", "garbage", "::1/128", "2001:db8::/32", "999.0.0.0/8", "10.0.0.0/-1"]:
    try:
        parse_ipv4_network(bad)
        check(f"reject {bad!r}", False)
    except InvalidCIDRError:
        check(f"reject {bad!r}", True)

# 裸 IP 合法（隐式 /32）
check("bare ip", str(parse_ipv4_network("10.0.0.1")) == "10.0.0.1/32")

# 10) 部分遮蔽跨多块的经典用例：已覆盖 .0/25，规则给 .0/24 -> 剩 .128/25
res, _ = analyze_rules([
    ("allow", "198.51.100.0/25"),
    ("deny",  "198.51.100.0/24"),
])
check("classic partial", res[1].effective_cidrs == ["198.51.100.128/25"], res[1].effective_cidrs)

# 11) 洞两侧非对齐：/24 去掉 .5/32
res, _ = analyze_rules([
    ("allow", "203.0.113.5/32"),
    ("deny",  "203.0.113.0/24"),
])
nets = res[1].effective_cidrs
check("hole .5 lossless",
      sum(ipaddress.ip_network(n).num_addresses for n in nets) == 255, nets)
check("hole .5 starts/ends", nets[0] == "203.0.113.0/30" and
      nets[1] == "203.0.113.4/32" and nets[2] == "203.0.113.6/31"
      and nets[-1] == "203.0.113.128/25", nets)

print("\n" + ("ALL PASS" if ok else "SOME FAILED"))
sys.exit(0 if ok else 1)
