# IPv4 CIDR 遮蔽分析 API

基于 **Python 3.12 + FastAPI** 的服务：接收一组**有序**的 `allow` / `deny` IPv4 CIDR
规则，逐条计算该规则中**尚未被此前任何规则覆盖**的地址集合，并给出：

- 每条规则的遮蔽分类：
  - `full`（全生效）：与此前规则无任何重叠；
  - `partial`（部分遮蔽）：有一部分地址已被覆盖，剩余地址以**最少数量的 CIDR** 无损返回；
  - `shadowed`（完全遮蔽）：全部地址此前均已覆盖，无任何生效地址。
- 汇总：各类规则条数，以及实际生效的 `allow`、`deny` 地址总数。

遮蔽只看地址集合的并集，与规则动作无关（动作仅用于汇总 allow/deny 计数）。

## 地址与端口

| 用途 | 地址 |
| --- | --- |
| 分析接口 | `http://localhost:8000/analyze` （`POST`） |
| 健康检查 | `http://localhost:8000/health` |
| 交互式文档（Swagger UI） | `http://localhost:8000/docs` |
| OpenAPI Schema | `http://localhost:8000/openapi.json` |

容器内监听 `0.0.0.0:8000`，通过 Docker Compose 映射到宿主机 **8000** 端口。
如需修改端口，编辑 `docker-compose.yml` 的 `"8000:8000"`（左侧为宿主机端口）。

## 一条命令启动

前置要求：已安装 Docker 与 Docker Compose 插件。

```bash
docker compose up -d --build
```

启动后验证：

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

停止与清理：

```bash
docker compose down          # 停止并删除容器
docker compose down -v       # 连同匿名卷一并清理
```

查看日志：`docker compose logs -f`

## API 说明

### `POST /analyze`

**请求体**

```json
{
  "rules": [
    {"action": "allow", "cidr": "10.0.0.0/8"},
    {"action": "deny",  "cidr": "10.0.0.0/24"},
    {"action": "deny",  "cidr": "10.0.0.0/7"},
    {"action": "allow", "cidr": "192.168.0.0/16"}
  ]
}
```

- `rules`（必填，至少 1 条）：**顺序即优先级**，按数组顺序处理；
- `action`：`allow` 或 `deny`；
- `cidr`：IPv4 CIDR，严格校验——网络地址必须对齐（如 `10.0.0.1/24` 非法，
  因其主机位非零）；裸 IP（如 `10.0.0.1`）按 `/32` 处理。

**响应示例**

```json
{
  "results": [
    {
      "index": 0,
      "action": "allow",
      "cidr": "10.0.0.0/8",
      "status": "full",
      "covered_addresses": 0,
      "effective_cidrs": ["10.0.0.0/8"]
    },
    {
      "index": 1,
      "action": "deny",
      "cidr": "10.0.0.0/24",
      "status": "shadowed",
      "covered_addresses": 256,
      "effective_cidrs": []
    },
    {
      "index": 2,
      "action": "deny",
      "cidr": "10.0.0.0/7",
      "status": "partial",
      "covered_addresses": 16777216,
      "effective_cidrs": ["11.0.0.0/8"]
    },
    {
      "index": 3,
      "action": "allow",
      "cidr": "192.168.0.0/16",
      "status": "full",
      "covered_addresses": 0,
      "effective_cidrs": ["192.168.0.0/16"]
    }
  ],
  "summary": {
    "total_rules": 4,
    "full_rules": 2,
    "partial_rules": 1,
    "shadowed_rules": 1,
    "allow_effective_addresses": 16842752,
    "deny_effective_addresses": 16777216
  }
}
```

字段说明：

| 字段 | 含义 |
| --- | --- |
| `results[].index` | 规则在输入数组中的下标（从 0 开始） |
| `results[].cidr` | 规范化后的 CIDR（裸 IP 补成 `/32`） |
| `results[].status` | `full` / `partial` / `shadowed` |
| `results[].covered_addresses` | 被此前规则覆盖的地址数 |
| `results[].effective_cidrs` | 未被覆盖地址的**最少 CIDR** 无损压缩；完全遮蔽时为 `[]` |
| `summary.allow_effective_addresses` | 所有 allow 规则实际生效（未被此前覆盖）的地址总数 |
| `summary.deny_effective_addresses` | 所有 deny 规则实际生效的地址总数 |

### 422 校验错误

以下情况返回 HTTP `422 Unprocessable Entity`（FastAPI 标准错误体，含 `loc` 定位）：

- `rules` 为空列表，或缺失、不是数组；
- CIDR 非法：格式错误、前缀越界（`/33`、`/-1`）、主机位非零（`10.0.0.1/24`）、
  地址段越界（`256.0.0.0/8`）等；
- CIDR 是 IPv6（如 `2001:db8::/32`、`::1`）——本服务仅支持 IPv4；
- `action` 不是 `allow` / `deny`，或缺少必填字段；
- 请求体不是合法 JSON。

```bash
curl -i -X POST http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"rules":[]}'
# HTTP/1.1 422 Unprocessable Entity
```

## 算法说明

1. 把每个 CIDR 转成 32 位无符号整数区间 `[network, broadcast]`；
2. 维护“此前所有规则并集”的有序、已合并区间表（重叠/相邻即合并）；
3. 对当前规则区间做集合减法，得到剩余地址区间；
   - 剩余为空 → `shadowed`；完全未覆盖 → `full`；否则 → `partial`；
4. 剩余区间用贪心算法压缩为最少 CIDR：每一步取“起点对齐且不越过区间终点”
   的最大 2 的幂地址块，直到覆盖整个区间。该贪心对区间→前缀表示是最优的；
5. 把当前规则整段并入已覆盖集合，继续下一条。

整个过程基于整数区间运算，不依赖枚举地址，支持 `0.0.0.0/0`（2³² 个地址）这类大段。

## 本地开发（不使用 Docker）

需要 Python 3.11+：

```bash
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

## 测试

仓库内含两个无外部服务依赖的测试脚本：

```bash
python test_analyzer.py   # 核心算法（分类、区间减法、最少 CIDR 压缩模糊测试、非法输入）
python test_api.py        # FastAPI 端到端（200/422、响应结构、IPv6 拒绝等）
```

## 项目结构

```
.
├── app/
│   ├── __init__.py
│   ├── analyzer.py     # 纯算法：CIDR 解析、区间合并/减法、最少 CIDR 压缩
│   └── main.py         # FastAPI 路由、Pydantic 校验与响应模型
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── test_analyzer.py
├── test_api.py
└── README.md
```
