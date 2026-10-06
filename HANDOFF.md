# PandaPass — 状态与后续计划

> 本文件是给下一次会话的交接文档。读完这份就能接着干，不用重新摸索代码。

## 已完成（全部有测试覆盖，`cargo test --workspace` 全绿）

**M1 核心（可用）**
- age 信封加密：成员公钥 + 服务端公钥双收件人，`server_age_identity` 可为 None
- 认证：邮箱密码（argon2）+ TOTP + 恢复码；session（HttpOnly cookie + CSRF 双提交）
- 服务令牌：SHA-256 哈希存储，scope 服务端强制（`read/write/list:secret`、`read:audit`、`manage:project`）
- RBAC：GlobalRole × ProjectRole × token scope 三维判定，见 `crates/pandapass-core/src/rbac.rs`
- 审计：写 SQLite，**永不记录 secret 值**（有测试断言）
- 项目/环境/密钥 CRUD、版本历史、软删除
- CLI：`login register keygen logout me project env secret member token config audit cred policy pki run inject`
- Web（Vue3 + Vite，无组件库，纯 CSS 变量）：Login / Dashboard / Project / Tokens / Audit / Policies / PKI / DynamicCreds
- 部署：distroless 镜像 + 内置 `--health-check` / `--init`（镜像里没有 shell，所以健康检查必须是二进制自己）
- 文档：`docs/SECURITY.md` `docs/DEPLOY.md` `docs/AGENT-INTEGRATION.md`
- 后台清理任务：过期 session + 过期动态凭证，60s 一轮

**API 测试**：`crates/pandapass-server/tests/api.rs`，20 个端到端用例，直接驱动 `build_router`（不起端口）。

## 没做完的（重要）

### 1. M2 动态凭证：只有 CRUD，没有真正的代理
现在 `cred create` 只是在库里生成一条带 TTL 的记录并返回随机密码。
**缺的是让那个密码真正生效的东西**：
- `crates/pandapass-server/src/routes/dynamic.rs` 只写库，不碰任何数据库
- 计划里的 PostgreSQL/MySQL 连接代理（`tokio-postgres` 转发 + 每连接改密码）没写
- Redis ACL 签发没写
- 验收标准「1 小时后同一凭证连接被拒」目前无法验证，因为没有东西在校验它

**下一步建议**：先做 PostgreSQL 只读代理。最小可用形态 = 一个 TCP listener，
握手时按 `username` 查 `dynamic_creds` 表（检查 `expires_at`/`revoked_at`），
用库里的密码去认证上游。这个能立刻让 TTL 变成真实的强制，而不只是 UI 上的灰字。

### 2. M3 策略引擎：表结构和 CRUD 有了，评估逻辑���空的
- `policies` / `policy_bindings` 表和 admin-only 的 CRUD 都在
- **没有任何地方调用策略**。`auth.can(perm)` 走的是硬编码的 RBAC 矩阵
- 计划里问过：OPA（Go 二进制）还是 `regorus`（纯 Rust）。**建议 regorus**，
  否则 distroless 镜像和「单机零依赖」的前提就破了
- 接法：在 `AuthContext::can` 之后加一层 `evaluate_policy(ctx, action, project, env) -> Result<(), Deny>`，
  被拒时返回 403 并把 policy_id 放进错误消息（计划要求「CLI 返回 403 且错误信息含策略 ID」）
- 绑定解析顺序：env 级 > project 级 > 全局

### 3. M4 PKI：存得下、管得了，但不会签
- CA 私钥用成员 MK 加密后入库，吊销位有；SSH 证书表有
- **服务端不签发任何东西**：`create_ssh_cert` 是「登记一张你已经签好的证书」，
  不是「签一张」；请求里 `cert_pem` 是客户端传进来的
- 缺：`rcgen` 签 X.509、`russh`/`ssh-crypto` 签 SSH 用户证书、
  Web 上的 `TrustedUserCAKeys` 下载页
- 注意 `list_ssh_certs` 现在是 admin-only。原设计允许用户看自己的，但
  service token 永远拿不到 `ManageUsers`，会让令牌路径全部 403，所以收紧了。
  要恢复自助查看，得给 session（非令牌）单独开一条 `user_id = self` 的路径。

### 4. GitOps 同步（计划里的 M3 后半）
完全没动。`.pandapass/project.yaml` + sops 加密的 `secrets/*.yaml`，双向 diff。

### 5. 秘密扫描（M4）
没动。计划是集成 trufflehog。注意：扫描**结果**不能把命中的明文写进审计日志，
和 secret 值同一原则。

## 已经知道的技术债

- `internal_exec` 返回 501 Not Implemented。`pandapass run` 本地做同样的事且更安全
  （age 私钥不出本机），所以**没有实现它的计划**，见 `docs/AGENT-INTEGRATION.md`
- 审计动作名还留着 `mcp_*` 前缀（数据库里存的是字符串，改名等于篡改历史）
- MCP server 已按用户要求删除，改为 CLI + `.claude/skills/pandapass/SKILL.md`。
  理由写在 `AGENT-INTEGRATION.md`：MCP 工具返回值 = 进 LLM 上下文，
  和 `secret get` 没有区别；只有 `run` 的进程注入真正让值不进上下文
- Web 的 DynamicCredsView 环境写死 `prod`（有 TODO）
- Web 上传 CA 私钥走表单 textarea，会进浏览器历史/内存。真要做得改成
  本地签好只上传公钥，或者走一个不经过 JS 的一次性上传端点

## 验证方式（每次都跑）

```bash
cargo test --workspace            # 37 个测试
cd web && npm run typecheck && npm run build
cargo build --workspace --release # 二进制名是 pandapass-cli / pandapass-server
```

计划里的端到端验收还有一项没自动化：**离线解密**。拷走 `data/` 目录，
在没有 age 私钥的机器上尝试解密，必须失败。

## 约定

- 提交信息尾部加 `Co-Authored-By: Claude Code <noreply@anthropic.com>`
- 用中文回复
- 小步提交，不要频繁汇报
