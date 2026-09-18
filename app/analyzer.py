"""IPv4 CIDR 遮蔽分析核心逻辑（与 Web 框架无关的纯函数）。"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

MAX_IP = (1 << 32) - 1


class InvalidCIDRError(ValueError):
    """非法 CIDR（含 IPv6、主机位非零等）。"""


@dataclass(frozen=True)
class RuleResult:
    index: int
    action: str
    cidr: str
    status: str  # full | partial | shadowed
    covered_addresses: int
    effective_cidrs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Summary:
    total_rules: int
    full_rules: int
    partial_rules: int
    shadowed_rules: int
    allow_effective_addresses: int
    deny_effective_addresses: int


def parse_ipv4_network(text: str) -> ipaddress.IPv4Network:
    """严格解析 IPv4 CIDR，拒绝 IPv6、非法前缀长度及主机位非零。"""
    try:
        network = ipaddress.ip_network(text, strict=True)
    except (ValueError, TypeError) as exc:
        raise InvalidCIDRError(f"非法 CIDR: {text!r} ({exc})") from exc
    if network.version != 4:
        raise InvalidCIDRError(f"仅支持 IPv4，收到 IPv6: {text!r}")
    return network


def merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """合并重叠/相邻的闭区间（以整数表示的 IP 范围）。"""
    if not intervals:
        return []
    intervals = sorted(intervals)
    merged: list[list[int]] = [list(intervals[0])]
    for start, end in intervals[1:]:
        if start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def subtract_intervals(
    target: tuple[int, int], covered: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """从目标区间 target 中减去已合并的 covered 区间，返回剩余区间。"""
    remaining: list[tuple[int, int]] = []
    cursor, end = target
    for c_start, c_end in covered:
        if c_end < cursor:
            continue
        if c_start > end:
            break
        if c_start > cursor:
            remaining.append((cursor, c_start - 1))
        cursor = max(cursor, c_end + 1)
        if cursor > end:
            break
    if cursor <= end:
        remaining.append((cursor, end))
    return remaining


def range_to_cidrs(start: int, end: int) -> list[str]:
    """把闭区间 [start, end] 无损压缩为最少数量的 CIDR 字符串。

    贪心：每一步在“不越过 end、不超过 /32”的前提下取最大对齐块。
    """
    cidrs: list[str] = []
    while start <= end:
        max_size_bits = (start & -start).bit_length() - 1 if start else 32
        size_bits = min(32, max_size_bits)
        while size_bits > 0 and start + (1 << size_bits) - 1 > end:
            size_bits -= 1
        prefixlen = 32 - size_bits
        cidrs.append(str(ipaddress.IPv4Network((start, prefixlen))))
        start += 1 << size_bits
    return cidrs


def intervals_to_cidrs(intervals: list[tuple[int, int]]) -> list[str]:
    """把剩余区间集合无损压缩成最少 CIDR。"""
    cidrs: list[str] = []
    for start, end in merge_intervals(intervals):
        cidrs.extend(range_to_cidrs(start, end))
    return cidrs


def analyze_rules(rules: list[tuple[str, str]]) -> tuple[list[RuleResult], Summary]:
    """按顺序分析 allow/deny 规则。

    rules: 已校验非空的 (action, cidr 文本) 列表。
    每条规则的“此前已覆盖集合” = 之前所有规则的并集（与 action 无关）。
    """
    covered_so_far: list[tuple[int, int]] = []
    results: list[RuleResult] = []
    allow_total = deny_total = 0
    full_count = partial_count = shadowed_count = 0

    for index, (action, raw_cidr) in enumerate(rules):
        network = parse_ipv4_network(raw_cidr)
        start = int(network.network_address)
        end = int(network.broadcast_address)
        size = end - start + 1

        remaining = subtract_intervals((start, end), covered_so_far)
        remaining = merge_intervals(remaining)
        covered_count = size - sum(e - s + 1 for s, e in remaining)

        if not remaining:
            status = "shadowed"
            effective_cidrs: list[str] = []
            shadowed_count += 1
        elif covered_count == 0:
            status = "full"
            effective_cidrs = intervals_to_cidrs(remaining)
            full_count += 1
        else:
            status = "partial"
            effective_cidrs = intervals_to_cidrs(remaining)
            partial_count += 1

        remaining_count = size - covered_count
        if action == "allow":
            allow_total += remaining_count
        else:
            deny_total += remaining_count

        covered_so_far = merge_intervals(covered_so_far + [(start, end)])
        results.append(
            RuleResult(
                index=index,
                action=action,
                cidr=str(network),
                status=status,
                covered_addresses=covered_count,
                effective_cidrs=effective_cidrs,
            )
        )

    summary = Summary(
        total_rules=len(rules),
        full_rules=full_count,
        partial_rules=partial_count,
        shadowed_rules=shadowed_count,
        allow_effective_addresses=allow_total,
        deny_effective_addresses=deny_total,
    )
    return results, summary
