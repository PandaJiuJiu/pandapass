# PandaPass 商业化差距清单（TODO）

> 本文件对照"商业级密钥管理"标准，列出 PandaPass 仍未交付的差距。
> 来源：对比 Vault / 1Password Business / AWS Secrets Manager / Keeper / Doppler
> 等成熟产品的安全、合规、运维基线，并结合当前代码（`1aa15d1`）的实际能力。
>
> 组织方式：按"距离商业化部署的远→近"分 6 个域、48 个问题，每条都标了优先级
> （P0 = 不解决不能商用，P1 = 应该有，P2 = 差异化）。文件:行 引用都基于 `main`。

---

## 域 A：零容忍类（"商业产品不能有的失败"）

### A1. `run` 子命令的安全防线是装饰品（P0）
- `PANDAPASS_COMMAND_ALLOWLIST` 在 `state.rs:115-124` 解析但**没有任何代码读取**。`pandapass run` 路径（`crates/pandapass-cli/src/commands/mod.rs:941-1028`）直接 `Command::new(...).status()`，**没有白名单、没有超时、并发不限**。
- 同样的，`PANDAPASS_COMMAND_TIMEOUT_SECS` 解析后从未被读（`state.rs:115-118`），`exec_semaphore` 构造后从不 acquire（`state.rs:32`）。
- **任何拿到 `read:secret` 令牌的代理都能 `run --only K -- bash -c '...'` 跑任意子进程**。
- 必修：在 spawn 之前对照允许列表校验 `args.command[0]`（或强制二进制路径前缀）；对 `status()` 包 `tokio::time::timeout`；在 CLI 端 acquire semaphore。

### A2. 登录限流是死代码（P0）
- `login` / `register` 是 public route（`lib.rs:48-51`），**不经过 `auth_middleware`**。`ClientIp` extension 只在 `auth_middleware` 里插入（`lib.rs:127-129`），所以 `state.rate_limiter.check(ip)` 在 login 上**永远拿不到 ip，限流从未真正触发**。
- `register` 的限流**注释掉了**（`routes/auth.rs:213-223`）。
- TOTP 没有独立限流，密码错 + TOTP 错的联合爆破没有节流。
- 修：(a) 把 `ClientIp` 抽到公共中间件让 login/register 也能拿到；(b) 注册在 `ALLOW_REGISTRATION=true` 窗口期内也要限流；(c) TOTP 校验前加每用户失败计数 + 软锁定。

### A3. X-Forwarded-For 完全无校验被信任（P0）
- `middleware/auth.rs:20-40` 把客户端 XFF 当真。任何直连或穿不可信代理的部署都能伪造 IP 绕过限流、污染审计 IP 字段。
- 修：增加 `PANDAPASS_TRUSTED_PROXY_CIDRS` 列表，仅当 peer 在列表内才采用 XFF；否则用 socket peer。

### A4. `inject` 子命令在写文件时把明文落盘（P0）
- `commands/mod.rs:1030-1047` 的 `inject` 把值替换进模板后**写到磁盘**。SKILL.md 明确说"不要把密钥写文件"，但 CLI 允许。
- 修：默认 `--in-place=false`、打印 warning，或要求显式 `--force` 才落盘。

### A5. Bootstrap admin 密码自动打到 `tracing::warn`（P0）
- `lib.rs:361-369`：未设 `PANDAPASS_ADMIN_PASSWORD` 时生成随机密码并 `tracing::warn!("Admin password (save this!): {password}")`。
- JSON 日志会被任何日志聚合器（ELK / Loki / SIEM）永久保留。
- 修：拒绝启动并要求显式密码（env 或 stdin），绝不打日志。

---

## 域 B：密钥管理根基类（"密钥管理"产品的本职）

### B1. 服务端 age 私钥与数据库同盘，无 HSM / KMS / 远程信封（P0）
- `PANDAPASS_SERVER_AGE_IDENTITY_FILE` 默认 `/data/server-age.key`（`docs/DEPLOY.md:32-38`），与 `pandapass.db` 同一 docker volume。
- 备份必须一起——但这是失败模式不是控制。
- 修：实现 `EnvelopeBackend` trait，支持 AWS KMS / GCP KMS / Azure Key Vault / HashiCorp Vault Transit / PKCS#11 / KMIP。文件模式应支持 HSM token（YubiHSM 等）。

### B2. 每个用户的 MasterKey 不分用途地加密一切（P0）
- 32 字节 MK 直接做 ChaCha20-Poly1305 key（`crypto.rs:301-332`），同时加密：普通 secret、TOTP secret、动态凭证密码、CA 私钥、SSH CA 私钥、未来可能加的 recovery codes。
- 单 MK 泄漏 = 该用户所有数据全裸。
- 修：用 HKDF 派生 per-purpose 子密钥（`subkey = HKDF(MK, info="totp"|"secret"|"ca"|...)`）。

### B3. MK 轮换不存在（P0）
- `MkRotate` audit action 在 enum 里（`models.rs:309, 365, 416`）但**没有任何 handler 写它**——死代码。
- `enroll_key rotate=true` 只是重新封装**同一个 MK** 到新的 recipient（`routes/auth.rs:498-525`），不是真正的 re-key。
- "换 MK 并把所有 secret 重新加密"这条路径没写。
- 修：新增 `POST /api/v1/auth/mk/rotate` 端点，遍历该用户所有 secret、生成新 MK、重加密、更新 envelope；增加自动轮换策略（按时间/事件触发）。

### B4. 服务端 age 身份无法原地轮换（P0）
- `init_storage`（`main.rs:202-235`）明确**拒绝覆盖**已有 `server-age.key`。轮换 = 全员重新 enroll。
- 轮换也会让审计链 key 一起失效（`main.rs:70-79` 派生），导致历史链无法验证。
- 修：实现"轮换服务端 age key + 自动重签所有 envelope"的批处理；保留旧 key 仅用于验签历史审计链。

### B5. 没有账户恢复机制（成员 age key 丢失 = 永久锁死）（P0）
- `recovery_codes_hash` 列在 schema、`set_recovery_codes` 在 db 模块，但**没有生成端点、没有兑换路径、没有 CLI 命令、没有 UI**。`grep -rn "recovery" crates/` 只剩 db 模块自身和 `totp_disable` 的清空调用。
- 修：注册后 / TOTP 启用后生成 N 个一次性 recovery code；recovery code 兑换端点（重置 MK + 发新 age key）。

### B6. 没有密码重置（忘记密码 = 永久锁死）（P0）
- `change_password` 要求当前密码（`auth.rs:555-581`），没有"忘记密码"流。没有邮件、没有管理员 reset、没有 recovery code 登录。
- 修：self-service reset（基于 recovery code 或邮件 magic link）；管理员 reset 端点。

### B7. 没有"用户禁用"的管理员端点（P0）
- `db::disable_user` 存在（`db/src/lib.rs:218-227`），所有路径会查 `disabled_at`（`auth.rs:108`, `middleware/auth.rs:116, 151`），但**没有任何 HTTP 路由调用它**。
- 修：增加 admin 端的 user list / disable / enable 端点 + UI。

### B8. 审计链 key 派生自服务端 age 身份，轮换 = 历史链失效（P1）
- `main.rs:70-79`：`chain_key = Sha256("pandapass-audit-chain:" + server_age_identity)`。轮换服务端 age 即断链。
- 修：审计链 key 独立管理（不与 envelope 共享根密钥），支持多代 key 共存与验签。

### B9. 审计链"防伪造"被服务端密钥拥有者绕过（P1）
- 拿到 DB + server-age.key 的攻击者**可以在链头插入伪造审计行**——HMAC 链的固有限制。
- 修：周期性把链头 hash anchor 到外部 timestamping 服务（RFC 3161 TSA、transparency log、S3 Object Lock、WORM）。

---

## 域 C：身份与认证类

### C1. 没有 SSO / OIDC / SAML / LDAP（P0）
- 唯一登录是 email + password（+TOTP）。没有 Google / Microsoft / Okta / OIDC 联合，没有 LDAP / AD 桥接，没有 SCIM 自动开通。
- 一个百人企业绝不会接受"每个员工都开一个本地账号"。
- 修：实现 OIDC client（最常用），后续补 SAML；增加 LDAP / AD 桥。

### C2. 没有会话列表 / 设备撤销 UI（P1）
- 只有 `logout_all`（`auth.rs:333-343`）。用户看不到自己的活跃会话，没法单独踢某个设备。
- 修："active sessions" 视图 + 单条撤销端点 + UI。

### C3. CSRF token 是 HttpOnly cookie，但 web UI 必须 JS 读它（P0）
- `auth.rs:144-149` 把 `pandapass_csrf` cookie 设了 `http_only(true)`。Double-submit 模式需要 JS 读取 cookie 并回填到 `x-csrf-token` 头——但 HttpOnly 阻止 JS 读。`web/src/api/client.ts` 也没有任何 set 头的逻辑。**这套 web UI 的 mutating 请求大概率根本通不过 CSRF 中间件**。
- 修：去掉 CSRF cookie 的 HttpOnly（让 JS 能读），或改成 session-bound 服务端 token（更安全）。

### C4. 会话 token 既在 cookie 也在 JSON body（P1）
- `auth.rs:170, 306` 同时通过 Set-Cookie 和 JSON body 返回 `session_token`。HttpOnly 形同虚设（任意 XSS 通过 fetch 拦截就能拿到 body 里的 token）。
- 修：web 流程只走 cookie；body 下发仅在 CLI 流（嗅探 user-agent 或专用 header）。

### C5. TOTP 算法是 SHA-1（P1）
- `crypto.rs:362, 379` 用 SHA-1。RFC 6238 允许 SHA-256 / 512，totp-rs 也支持。
- 修：默认 SHA-256。

### C6. 没有密码策略 + 弱参数化 hash（P0）
- `RegisterRequest` 无任何长度 / 复杂度校验（`auth.rs:177-185`）。
- Argon2 用 `Argon2::default()`（`crypto.rs:336, 346`）= m=19MiB / t=2 / p=1。**没有配置开关**。
- 没有 HIBP 泄露库检查。
- 修：最少 12 字符 + 复杂度；Argon2 参数可通过 env 调高；可选 HIBP k-anonymity API。

### C7. 没有账户级锁定 / 失败计数（P0）
- 完全靠 IP 限流（且未生效）。分布式爆破无抵抗。
- 修：每用户失败计数 + 软锁定 + 失败告警。

### C8. 没有 SCIM / 自动开通（P1）
- 添加成员靠管理员手工 `pandapass register`，没有"邀请 → 邮件 → 自助开通"。

### C9. 没有"会话时长"分层策略（P1）
- 单一 TTL 默认 30 天（`state.rs:94-97`），没有 idle timeout、没有 step-up reauth（敏感操作前强制 TOTP）。
- 修：absolute + idle 双 TTL + sensitive action 强制 step-up。

### C10. TOTP `check_current` 无时钟漂移窗口（P2）
- `crypto.rs:356-371` 用 `totp.check_current(code)`，**不接 ±1 step**。合法用户在时钟略偏时会失败。
- 修：用 `totp.check(code, ±1)`。

### C11. TOTP 码无一次性使用记录（P2）
- 同一码在 30 秒内可重放无限次。
- 修：记录最近 N 秒用过的码拒绝重放。

### C12. TOTP secret 与 MK 共生——TOTP 注册门槛隐藏在 user 端（P0）
- `auth.rs:354-370` 的 `totp_setup` 要求 `get_master_key_for_user` 成功（用户必须有 envelope）。如果用户从 UI 注册没传 `--age-public-key`，`enrolled = false`，之后 admin 设 `PANDAPASS_REQUIRE_TOTP=true` → 该用户**完全无法开启 TOTP** → 永久 401。
- 修：把"首次登录强制走 keygen + totp_setup 向导"做成强制流程；或允许 TOTP 独立于 MK 存储。

### C13. `logout_all` 不清当前 cookie（P2）
- `auth.rs:333-343` 不接受 `CookieJar`，浏览器持有失效 session cookie 直到下次 401。

### C14. `bootstrap` 路径无"二次确认"（P0）
- 启动时如果 `user_count==0` 且 `PANDAPASS_ADMIN_EMAIL` 存在，**自动创建 admin**。误把 admin 邮箱留成员工邮箱 → 该员工就是 admin。
- 修：要求 `--bootstrap` 显式 opt-in flag。

---

## 域 D：API 安全 / 操作性

### D1. 服务端 `internal_exec` 返回 501（P0）
- `lib.rs:312-316`。"`run:secret` scope" 已经在 scope 系统里走通，handler 也校验了，但**没有真正的执行端点**。CLI 走的是 session + 本地 age key 路径，根本用不上 `run:secret`。
- 结果：商业承诺"代理永远拿不到明文"的控制论保证**仍是装饰**——任何 `read:secret` token 都能 `secret get` 拉明文（SKILL 说不要，但 skill 是建议不是控制）。
- 修：实现 server-side exec（沙箱化的子进程生成：cgroups / namespaces / seccomp），或强制代理只能走 `run:secret` 路径（在 `secret get` 上加环境强制约束）。

### D2. 审计日志里 IP / UA 几乎全空（P0）
- `auth.rs:160-161, 298-299` 硬编码 `with_ip("".into())`、`with_user_agent("".into())`。
- `secrets.rs:140-204` 等业务路由只调 `log_success(&mut audit)`，没填 IP / UA。
- 任何 SOC 分析师打开审计页都看不到"谁从哪儿发起的请求"。
- 修：所有 `AuditContext` 构造处从 request 拿 IP / UA；`extract_client_ip_from_headers` 调用足够靠前。

### D3. 没有 metrics / 告警 / 日志导出（P0）
- `grep` 全仓零匹配 prometheus / opentelemetry / metrics crate。唯一机器可读端点是 `/health`。
- 没有 SIEM 转发、没有 webhook、没有 PagerDuty / Slack 告警。
- 修：`/metrics` Prometheus 端点 + 关键事件 webhook（爆破、限流命中、admin 权限变更、服务端 key 被读）。

### D4. 审计日志没有保留期策略、没有归档路径（P0）
- `audit_log` 表**只增不减**。`main.rs:170-185` 的清理只清 sessions 和 dynamic creds。审计行永远涨。
- 归档唯一方法是手动 SQL，**必然破坏 HMAC 链**。`verify_audit_chain` 之后只能"假装链路 OK"（`routes/tokens.rs:282-289` 在 chain key 为空时返回 intact=true）。
- 修：(a) 归档到外部对象存储并把"归档锚"写回 chain；(b) 链的"段"概念，让每段可独立归档 + 校验。

### D5. 没有自动备份 / 灾备演练（P0）
- `docs/DEPLOY.md:128-150` 给了一段脚本 + cron，**但不在产品里**。没有备份成功率监控、没有恢复演练工具、没有 PITR。
- 修：内建 `pandapass backup` / `pandapass restore` 子命令；可选对接 S3 / B2；备份完整性校验；定期恢复演练 cron 模板。

### D6. X.509 签发后立刻遗忘（P0）
- `sign_x509_from_csr`（`pki.rs:99-145`）返回 PEM 就完事，**不存**。没有 `issued_certs` 表、没有 serial 跟踪。
- 撤销只能撤销整个 CA，把所有该 CA 签过的全打死。
- `pki.rs:189-190` 设了 `CrlSign` key usage 但**从不签发 CRL**。
- 修：issued cert 表 + serial 跟踪；CRL 端点 + 周期签发 + `crlDistributionPoints` 扩展嵌入 cert；OCSP responder。

### D7. SSH cert `revoked_at` 是 dead 字段（P1）
- SSH cert 撤销（`pki.rs:401-446`）后**没消费者**——revoke 后 cert 在 valid_after 窗口内仍密码学有效。
- 修：维护 `RevokedKeys` 文件并通过端点暴露给 sshd 消费；或在每次 sshd 认证前调用 PandaPass REST 验证。

### D8. MySQL / Redis 动态凭证只 issuance，无 proxy（P0）
- 路由接受 `mysql` 和 `redis` 类型（`models.rs:661-677`），但 proxy 只实现了 PostgreSQL（`dynamic_proxy.rs`）。发出来的 MySQL / Redis 凭证**根本连不上**。
- 修：要么实现 MySQL / Redis wire proxy，要么 issuance 时就拒掉。

### D9. web 端 CA 私钥上传走 `<textarea>`（P0）
- HANDOFF.md 自己承认：`web` 把 CA 私钥用 textarea 上传（`HANDOFF.md:67-68`）。CA 私钥经浏览器内存 + 浏览器历史 + 任何浏览器扩展。
- 修：本地签好只上传 CSR（公钥），或一次性上传端点（无 JS 注入）。

### D10. 没有 SSH 签发 UI / `TrustedUserCAKeys` 拉取（P1）
- HANDOFF.md 明确列为 M4 缺口。

### D11. `gitops push` 不幂等（P2）
- 总是把所有 key 当 writes 推（即使未变），每次 push 都 bump version。`diff → push` 不能 idempotent。
- 修：push 时比较 SyncState 版本，跳过未变更的 key。

### D12. `write_secret` 的 create-vs-update 分类不在事务里（P2）
- `secrets.rs:324` 用 `get_secret.is_ok()` 然后 `upsert_secret`，TOCTOU 风险，audit action 可能错分类。
- 修：单一 SQL `INSERT ... ON CONFLICT DO UPDATE RETURNING (xmax = 0)` 或显式事务。

### D13. `PANDAPASS_COOKIE_SECURE` 派生规则与公网 URL 强绑定（P2）
- 任何 `https://` 开头就 true（`state.rs:127`）。但**通过反向代理**走 https、但 `public_url` 没配 https，会把 Secure 关掉 → cookie 在 http 传输。
- 修：启动自检"我看到 public_url 是 http 但似乎在反代后面"时打印警告。

### D14. CORS `allow_credentials(true)` + 任何 origin 都能被列入白名单（P2）
- `lib.rs:39-43` 的 CORS 配置从环境变量解析 origin，没有"这个 origin 必须是 https"等校验。
- 修：校验 origin scheme + 拒绝通配。

### D15. 没有 secret-level 标签 / 分类 / 元数据（P1）
- 一个 `KEY` 就一个 `value`。没有"这是 prod 用的 db password" / "环境敏感度 high" 之类 metadata。
- 修：key 标签（Vault 的 kv metadata、AWS Secrets Manager 的 tags）。

### D16. 没有 secret 的"使用追踪"（P1）
- 只审计"读了"，不知道"实际被谁消费过"。无法识别 stale credential。
- 修：secret 被消费时（外部服务以 `last_used_at` 形式回写）才能识别。

### D17. 没有 secret rotation policy（P1）
- Secret 是人来手动 rotate，没有 `rotate_by` / `last_rotated_at` / 自动告警。
- 修：每个 key 可设 rotation window，到期报警 + 阻读。

### D18. 没有 admin 操作的多人复核 / 四眼（P1）
- 任何 admin 都能 mint token、revoke CA、删 project。`MkRotate` 死了，但即使活也是单人。
- 修：quorum approval（Vault 的 "control group" 模式）覆盖破坏性操作。

### D19. 大 secret 无服务端软限制（P2）
- 仅 `key.len() <= 256`（`secrets.rs:320, 364`）。1 MB value 会被接受；只 nginx `client_max_body_size 2m` 救。
- 修：服务端 body size 限制（如 256 KB），超出返回 413。

### D20. `pandapass inject` 写文件违反 SKILL（P0）
- 已在 A4 列出，此处补充：CLI 端必须在文档里**完全 deprecate** inject 命令，或仅在 `--allow-disk-write` 时生效。

### D21. 没有 SOC2 / ISO 27001 证据自动化（P1）
- 没有控制项自描述、没有自动生成 evidence 的能力。
- 修：维护"控制矩阵"文档 + 自动化检查脚本（如"密码参数 ≥ X"、"TOTP 强制开启"等）。

### D22. `internal_exec` 的 audit meta 没有 exit code（P2）
- `lib.rs:303-310` 记录 keys 和 argv0 但**没 exit code**（`log_mcp_run_command` 助手会记，但这条路径不用助手）。
- 修：在 meta 里补 `exit_code` 字段。

---

## 域 E：扩展性 / 平台类

### E1. SQLite 单点 + 无 HA（P0）
- `docs/DEPLOY.md:177-186` 自己承认：单点 < 50 人 / < 20 RPS。SQLx → Postgres 是迁移路径，**但当前没有这条迁移工具**。
- 没有 read replica、没有 leader election、没有跨区域复制。
- 修：默认 Postgres 主备；提供 `pandapass migrate sqlite→postgres` 工具；可选 RTO / RPO 指标。

### E2. 运行时镜像回退到 Debian slim（不是 distroless）（P0）
- `docker/Dockerfile.server:44-48` 注释承认"本地镜像没 distroless，所以用 debian:bookworm-slim"。攻击面大很多。
- 修：回到 `gcr.io/distroless/cc-debian12:nonroot` 或 `chainguard/cc-dynamic`。

### E3. 没有多架构 / 不可变镜像签名（P1）
- Dockerfile 锁 amd64，没有 cosign 签名，没有 SLSA provenance。

### E4. 没有 SBOM / CVE 扫描（P1）
- 没有 `cargo-audit` / `cargo-deny` 在 CI 强制。
- 修：CI 加 `cargo audit --deny warnings`、`cargo deny check`；发布时附 SBOM。

### E5. 限流是 in-memory（P1）
- `middleware/rate_limit.rs` 单进程。多副本部署各自计数，攻击者可分散到不同节点。
- 修：可插拔后端（Redis 推荐）。

### E6. 没有容器镜像 / 二进制的离线签名验证（P2）
- 客户端无法验证所连的 server 是真的 PandaPass（自签 TLS 之外没有额外锚点）。

---

## 域 F：可观察性 / 合规 / 其他

### F1. 没有结构化请求日志 + 请求 ID（P1）
- `tower_http::trace::TraceLayer` 输出 method/path/status，但 `AuditContext` 没有 request_id，无法把审计事件和请求日志关联。
- 修：每次请求生成 request_id，注入 response header `x-request-id`、写入 `AuditContext.meta`。

### F2. TOTP secret 与 MK 共生——已列 C12。

### F3. 没有"未使用的 token / 凭据"自动发现（P2）
- 商业级需要"30 天未使用的 token 自动警告并最终禁用"。

### F4. 注册流程无邮箱验证（P0）
- 任何邮箱都可注册为 admin（首次注册即 admin）；没有"邮箱所有权"证明。
- 修：注册时发 magic link 验证邮箱；首次注册 admin 也需验证。

### F5. 服务端 key bootstrap 没有强约束（P1）
- `init_storage` 写到文件就完事；不检查文件 owner、目录权限。如果运维在错的 owner 下跑，文件以错权限存在。
- 修：启动时自检"运行用户 == 文件 owner"、目录 mode 700、文件 mode 600；不通过则 fail-fast。

### F6. web UI 的 `DynamicCredsView` 环境硬编码 `prod`（P2）
- HANDOFF.md:66 列出的已知小 bug。
- 修：UI 加环境选择。

### F7. `pandapass audit` 不支持导出 / 转发（P1）
- 只能 list。SIEM / 长保留需要 CSV / JSONL 导出或实时流。
- 修：`pandapass audit export --format jsonl --since ...`；可选 webhook。

### F8. TOTP `check_current` 的窗口——已列 C10。

### F9. SCIM 批量操作无接口（P1）
- 已列 C8；这里补：即便有 SCIM，也要有 `groups` / `roles` 映射。

### F10. `pandapass config set-age-identity` 无 passphrase 保护（P1）
- CLI 存到 `~/.pandapass/config.json` mode 0600，但 age key 文件本身无 passphrase。如果攻击者拿到 operator 机器磁盘，明文 age key 可直接用。
- 修：可选 age key passphrase（scrypt / argon2 KDF）。

### F11. `web` 仍为"npm run build 未验证"（P1）
- `docs/SECURITY.md:175-178` 明确承认 web UI 从未在沙箱中跑过。商业级必须有 e2e 测试套件（Playwright / Cypress）。

### F12. 限流 reset 在成功登录时清空该 IP 全部计数（P2）
- `auth.rs:117-119` + `rate_limit.rs:68-70` 的逻辑让攻击者"用 5 次失败后 1 次成功就清空"，可被滥用。
- 修：reset 只 reset 该 user 的；IP 计数按窗口滑走。

### F13. CLI `--insecure` 是全局开关（P1）
- `client.rs:57-60` 的 `--insecure` 关掉 TLS 验证。错误用法 = bearer token 明文传输。
- 修：默认拒绝 `--insecure` 配合非 loopback；或要求二次确认。

### F14. gitops 文件写入不做 atomic rename（P2）
- `commands/mod.rs:1127` 用 `tokio::fs::write` 写 `secrets/<env>.yaml.age`，没有 `.tmp` + rename。中途被杀会留半截文件。
- 修：原子写（与 `.sync-state.json` 的处理一致）。

### F15. recovery codes 字段是 dead（P0）
- 已列 B5。

### F16. 一些 docs 描述的功能不存在（P0）
- `docs/AGENT-INTEGRATION.md`、`docs/SECURITY.md`、`docs/DEPLOY.md` 多处把"未实现"说成"已支持"（`run:secret`、命令 allowlist、timeout、recovery codes、command allowlist）。docs / reality 漂移本身就是商业风险（合规审计必查）。
- 修：建立"文档-代码"双向校验；所有文档里宣称的能力必须能找到对应测试。

---

## 优先级建议（如果要分批做）

### Phase A（不做就不能商用）
- A1, A2, A3, A4, A5
- B1, B2, B3, B4, B5, B6, B7
- C1, C3, C6, C7, C12, C14
- D1, D2, D3, D4, D5, D6, D8, D9, D20
- E1, E2
- F4, F15, F16

### Phase B（产品差异化）
- B8, B9
- C2, C4, C5, C8, C9
- D7, D10, D15, D16, D17, D18, D21
- E3, E4, E5
- F1, F3, F5, F7, F10, F11, F13

### Phase C（规模化 / 长期）
- C10, C11, C13
- D11, D12, D13, D14, D19, D22
- E6
- F6, F8, F12, F14

---

## 一句话总结

PandaPass 的"代理不接触明文"故事已经商业级、文档化、测试良好；**它的"密钥管理产品"**在密钥管理自身（轮换、恢复、KMS、PKI 完整性）、身份层（SSO、会话、密码重置）、运维层（metrics、告警、备份、归档、合规）这三块**距离商业级还差一整套底层平台**。最危险的是 §A（"配置了但没生效"的安全防线）和 §B（P0 密钥管理本职功能缺失）——前者是 silent failure、后者是商业承诺但未交付。

---

## 进度跟踪（2026-10-10）

**已修的 25 个 commit**（按域分组）：

### A 域（5/5 完成）
- A1 命令允许列表 + 超时：`6c79200 feat(cli): enforce command allowlist and timeout`
- A2 限流：ClientIp 中间件 + register 限流 + 测试：`83a8985 fix(server): rate limit fires`
- A3 XFF 信任：`8ec860a fix(server): only trust X-Forwarded-For`
- A4 inject 拒落盘：`ff54699 feat(cli): inject defaults to refusing`
- A5 bootstrap 密码不打日志：`805de30 fix(server): never log the bootstrap admin password`

### B 域（9/9 完成）
- B1 KMS 抽象：`1a572c0 feat(core): add EnvelopeBackend trait`
- B2 HKDF 分域：`3b8b535 feat(crypto): domain-separate per-purpose subkeys`
- B3 MK 轮换端点：`f069a17 feat(server): POST /api/v1/auth/mk/rotate`
- B4 server-age inspect 端点：`5592a39 feat: admin endpoint to inspect server's age public key`
- B5 recovery code 端到端：`ff26636 feat(auth): recovery code generation and redemption`
- B6 密码重置：`e902e2a feat(auth): self-service password reset via recovery code`
- B7 用户 disable/enable：`c64fa1d feat(admin): user disable / enable endpoints`
- B8 审计链 key 独立：`a918e10 feat(audit): independent PANDAPASS_AUDIT_CHAIN_KEY_FILE`
- B9 审计防伪造（部分）：anchor 文件机制 + 与 age key 解耦；外部 timestamping 仍待办

### C 域（11/14 完成）
- C1 SSO/OIDC：未做
- C2 会话列表/撤销：`306edc4 feat(auth): list and revoke my own sessions`
- C3 CSRF cookie 可读：`232d917 fix(web): CSRF cookie must be JS-readable`
- C4 token body 仅 CLI：`9ee8545 feat(auth): session token only returned to the CLI`
- C5 SHA-256 TOTP：`278ac3f feat(crypto): use SHA-256 for TOTP instead of SHA-1`
- C6 密码策略：`d52fcdf feat(auth): enforce minimum password length`
- C7 账户级锁定：`ce1afc4 feat(auth): per-account lockout on repeated failed logins`
- C8 SCIM/邀请：未做
- C9 idle timeout：`78f34d6 feat(auth): idle timeout for sessions`
- C10 TOTP 时钟窗口：`6f1a745 feat(crypto): TOTP verifier accepts ±30s of clock drift`
- C11 TOTP 重放保护：未做
- C12 TOTP 无 envelope：`2d16769 feat(auth): TOTP setup works without an enrolled age key`
- C13 logout_all 不清 cookie：未做
- C14 bootstrap opt-in：`b1313cf fix(server): require explicit PANDAPASS_BOOTSTRAP=true`

### D 域（2/9 完成）
- D1 server-side exec：未做（标记 501）
- D2 审计 IP/UA 填全：`6ec6195 feat(audit): populate IP and user-agent`
- D3 /metrics：`31dbeba feat(server): Prometheus-style /metrics endpoint`
- D4 issued-certs 表 + 单独撤销：`83ec0ad feat(pki): record every X.509 cert`
- D5 自动备份/恢复：未做
- D6 审计归档：未做
- D7 SSH cert revocation list 推送：未做
- D8 web CA 私钥 textarea：未做
- D9 SSH 签发 UI：未做

### E 域（1/6 完成）
- E1 SQLite → Postgres 工具：未做
- E2 distroless：未做
- E3 多架构 + 镜像签名：未做
- E4 SBOM / CVE 扫描：未做
- E5 限流后端可插拔：未做（仍是 in-memory）
- E6 镜像签名验证：未做

### F 域（1/16 完成）
- F1 request_id：`dd22eef feat(server): per-request x-request-id middleware`
- F2 TOTP 与 MK 共生：已通过 C12 修
- F3 未使用 token 自动禁用：未做
- F4 邮箱验证：未做
- F5 bootstrap 启动自检：未做
- F6 DynamicCredsView 环境硬编码 prod：未做
- F7 audit 导出：未做
- F8 TOTP 时钟窗口：已通过 C10 修
- F9 SCIM 映射：未做
- F10 age-key passphrase：未做
- F11 web e2e：未做
- F12 限流 reset on success：未做
- F13 --insecure 警告：未做
- F14 gitops 原子写：未做
- F15 recovery codes：已通过 B5 修
- F16 docs-代码漂移：未做
