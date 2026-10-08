# PandaPass — 状态与后续计划

> 本文件是给下一次会话的交接文档。读完这份就能接着干，不用重新摸索代码。

## 已完成（全部有测试覆盖，`cargo test --workspace` 全绿）

**M1 核心（可用）**
- age 信封加密：成员公钥 + 服务端公钥双收件人，`server_age_identity` 可为 None
- 认证：邮箱密码（argon2）+ TOTP + 恢复码；session（HttpOnly cookie + CSRF 双提交）
- 服务令牌：SHA-256 哈希存储，scope 服务端强制（`read/write/list:secret`、`read:audit`、`manage:project`）
- RBAC：GlobalRole × ProjectRole × token scope 三维判定，见 `crates/pandapass-core/src/rbac.rs`
- 审计：写 SQLite，**永不记录 secret 值**（有测试断言）
- 审计链：HMAC-SHA256 链式防篡改，key 从 `server_age_identity` 派生；CLI/端点 `audit verify`
- 项目/环境/密钥 CRUD、版本历史、软删除
- CLI：`login register keygen logout me project env secret member token config audit cred policy pki run inject`，`audit verify`，`ssh sign`
- Web（Vue3 + Vite，无组件库，纯 CSS 变量）：Login / Dashboard / Project / Tokens / Audit / Policies / PKI / DynamicCreds
- 部署：distroless 镜像 + 内置 `--health-check` / `--init`（镜像里没有 shell，所以健康检查必须是二进制自己）
- 文档：`docs/SECURITY.md` `docs/DEPLOY.md` `docs/AGENT-INTEGRATION.md`
- 后台清理任务：过期 session + 过期动态凭证，60s 一轮

**API 测试**：`crates/pandapass-server/tests/api.rs`，25 个端到端用例，直接驱动 `build_router`（不起端口）。
**总测试数**：`cargo test --workspace` 63 个（core 31 + server 7 + api 25）。

## 没做完的（重要）

### 1. M2 动态凭证：只有 CRUD 和握手认证，没有真正的代理
PostgreSQL/MySQL 连接代理（`tokio-postgres` 转发 + 每连接改密码）只做了骨架：
- `crates/pandapass-server/src/dynamic_proxy.rs` 监听、握手、密码校验都已完成，但
  `handle_connection` 在认证后没有上游转发，直接给客户端返回 "not implemented" 并关闭。
- `main.rs` 没有启动代理（config 里没有 `proxy_listen` 字段）。
- Redis ACL 签发没写。
- 验收标准「1 小时后同一凭证连接被拒」目前只能被 CRUD TTL 覆盖，还没有真实代理验证。

### 2. M3 策略引擎：评估已接入 secrets 路由，但只限于 secrets
- `policies` / `policy_bindings` 表、admin-only CRUD、regorus 评估均已完成。
- secrets 路由在写/读/删除/版本/列表 5 处调用 `policy_engine.evaluate`。
- **其他资源（projects、members、tokens、creds、ca、ssh-certs）尚未接入策略**。

### 3. M4 PKI：SSH 证书已能签发，X.509 已能 CSR 签名，但还有缺口
- CA 私钥用成员 MK 加密后入库，吊销位有；SSH 证书表有。
- `/ca/{id}/sign-ssh` 已使用 `ssh-key` 签发 ed25519 用户证书，CLI `ssh sign` 已接。
- `/ca/{id}/sign`（X.509 from CSR）已使用 `rcgen` 实现。
- **Web 上没有 SSH 签发 UI**，也没有 `TrustedUserKeys` 公钥下载页。
- `list_ssh_certs` 是 admin-only。原设计允许用户看自己的，但 service token 拿不到
  `ManageUsers`，会让令牌路径全部 403，所以收紧了。要恢复自助查看，需要给 session
  单独开一条 `user_id = self` 的路径。

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
cargo test --workspace            # 63 个测试
cd web && npm run typecheck && npm run build
cargo build --workspace --release # 二进制名是 pandapass-cli / pandapass-server
```

计划里的端到端验收还有一项没自动化：**离线解密**。拷走 `data/` 目录，
在没有 age 私钥的机器上尝试解密，必须失败。

## 约定

- 提交信息尾部加 `Co-Authored-By: Claude Code <noreply@anthropic.com>`
- 用中文回复
- 小步提交，不要频繁汇报
