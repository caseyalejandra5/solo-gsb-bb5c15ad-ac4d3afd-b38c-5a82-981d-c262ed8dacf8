"""FastAPI 应用：IPv4 CIDR 遮蔽分析。"""

from __future__ import annotations

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

from .analyzer import InvalidCIDRError, analyze_rules

Action = Literal["allow", "deny"]


class RuleIn(BaseModel):
    action: Action = Field(..., description="规则动作：allow 或 deny")
    cidr: str = Field(..., description="IPv4 CIDR，例如 10.0.0.0/8")

    @field_validator("cidr")
    @classmethod
    def _validate_cidr(cls, v: str) -> str:
        # 非法 CIDR / IPv6 统一交给分析器的严格解析，错误会转成 422。
        from .analyzer import parse_ipv4_network

        if not isinstance(v, str) or not v.strip():
            raise ValueError("cidr 不能为空")
        parse_ipv4_network(v.strip())
        return v.strip()


class AnalyzeRequest(BaseModel):
    rules: list[RuleIn] = Field(..., min_length=1, description="有序规则列表，至少 1 条")


class RuleOut(BaseModel):
    index: int
    action: str
    cidr: str
    status: Literal["full", "partial", "shadowed"]
    covered_addresses: int
    effective_cidrs: list[str]


class SummaryOut(BaseModel):
    total_rules: int
    full_rules: int
    partial_rules: int
    shadowed_rules: int
    allow_effective_addresses: int
    deny_effective_addresses: int


class AnalyzeResponse(BaseModel):
    results: list[RuleOut]
    summary: SummaryOut


app = FastAPI(
    title="IPv4 CIDR 遮蔽分析 API",
    version="1.0.0",
    description=(
        "接收有序 allow/deny CIDR 规则，计算每条规则未被此前规则覆盖的地址集合，"
        "分为全生效（full）、部分遮蔽（partial）、完全遮蔽（shadowed），"
        "并将剩余集合无损压缩为最少 CIDR。"
    ),
)


@app.get("/", tags=["meta"])
def root() -> dict[str, str]:
    return {"service": app.title, "docs": "/docs", "health": "/health"}


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["analyze"],
    summary="分析规则遮蔽情况",
)
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    # pydantic 的 field_validator 已保证单条 CIDR 合法；这里二次保护，
    # 任何解析异常都转成 422。
    try:
        pairs = [(r.action, r.cidr) for r in req.rules]
        results, summary = analyze_rules(pairs)
    except InvalidCIDRError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return AnalyzeResponse(
        results=[
            RuleOut(
                index=r.index,
                action=r.action,
                cidr=r.cidr,
                status=r.status,  # type: ignore[arg-type]
                covered_addresses=r.covered_addresses,
                effective_cidrs=r.effective_cidrs,
            )
            for r in results
        ],
        summary=SummaryOut(**summary.__dict__),
    )
