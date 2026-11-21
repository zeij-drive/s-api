# StarryAPI

一个从零搭建的 Go API 中转站骨架：为调用方提供 OpenAI-compatible API，把请求按渠道、模型映射、分组、优先级和权重转发到上游，并提供管理员 HTTP API。

当前首版包括：

- OpenAI-compatible `POST /v1/chat/completions` 透传与 SSE 流式转发。
- `GET /v1/models`；渠道模型列表与模型映射；渠道组和用户 Key 组隔离。
- 按优先级/权重选择渠道；上游网络错误、HTTP 429/5xx 时尝试备用渠道。
- 管理渠道（新增、列表、查询、修改、删除、连通性测试）。
- 创建/禁用/删除调用方 API Key、模型白名单和 token 用量上限。
- 用量日志、prompt/completion token 汇总和健康检查。
- Docker 镜像和 GitHub Actions：PR 中执行测试与镜像构建检查；向 `main`/`master` 推送或推送 `v*.*.*` 标签时发布到 GHCR（`linux/amd64`、`linux/arm64`）。

这是可扩展的网关底座，不是 NewAPI 的完整 UI/功能复刻：目前仅内置 OpenAI-compatible 适配器，无渠道计费价格表、充值/兑换、支付、订阅系统、后台 Web UI 或完整的各厂商协议适配。渠道和存储采用轻量 JSON 文件，单实例适用；多实例部署前应替换为共享数据库并增加协调式限流/调度。上游 API Key 使用 AES-GCM 加密后写入状态文件。默认加密密钥保存在 `STORE_PATH.key`，生产环境建议设置独立的 `MASTER_KEY`，值为 64 位十六进制字符，并妥善备份密钥。请保护状态卷和管理接口。

## 本地运行

需要 Go 1.25+。
`ADMIN_TOKEN` 必须至少 32 个字符。

```powershell
$env:ADMIN_TOKEN = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$env:STORE_PATH = ".\data\state.json"
go run ./cmd/server
```

健康检查：`GET http://localhost:8080/healthz`

## 管理接口

管理接口均使用 `Authorization: Bearer $ADMIN_TOKEN`。

创建渠道（`models` 是对调用方公开的模型名；可用 `model_mapping` 将其映射到上游 ID）：

```sh
curl -X POST http://localhost:8080/admin/channels \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "name":"primary", "type":"openai-compatible",
    "base_url":"https://api.example.com/v1", "api_key":"UPSTREAM_TOKEN",
    "group":"default", "models":["chat-model"],
    "model_mapping":{"chat-model":"provider-model-id"},
    "priority":10, "weight":1, "enabled":true
  }'
```

`type` 目前接受 `openai-compatible` 或 `openai`。`base_url` 可带 `/v1` 后缀。创建 Key（密钥只在创建响应中返回一次）：

```sh
curl -X POST http://localhost:8080/admin/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"app-a","group":"default","models":["chat-model"]}'
```

返回的 `secret` 用于调用方请求；可通过 `PATCH /admin/keys/{id}` 设置 `enabled`、`models`、`group` 或 `quota_tokens`。渠道接口：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/admin/channels` | 列表 / 创建 |
| GET/PATCH/DELETE | `/admin/channels/{id}` | 查询 / 更新 / 删除 |
| POST | `/admin/channels/{id}/test` | 对上游 `/v1/models` 发起连通性测试 |
| GET/POST | `/admin/keys` | 列表 / 创建 |
| GET/PATCH/DELETE | `/admin/keys/{id}` | 查询 / 更新 / 删除 |
| GET | `/admin/usage?limit=100` | 最新用量日志 |

调用接口保持 OpenAI 客户端格式：

```sh
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $STARRYAPI_KEY" -H 'Content-Type: application/json' \
  -d '{"model":"chat-model","messages":[{"role":"user","content":"你好"}]}'
```

## Docker Compose

```sh
export ADMIN_TOKEN="$(openssl rand -hex 32)"
# 生产环境建议额外设置并在安全位置保存 32 字节主密钥
export MASTER_KEY="$(openssl rand -hex 32)"
docker compose up -d --build
```

默认端口为 `8080`，数据持久化在 `starryapi-data` 命名卷。GitHub Actions 会将主分支最新镜像标记为 `ghcr.io/<owner>/<repo>:latest`；标签推送会同时生成版本标签和 SHA 标签。
