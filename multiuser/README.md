# 多用户 per-user TUN + fake-ip 域名下发验证

独立 flake，验证 feasibility 方案落到真实场景（多用户 + 域名）时最不确定的两点：

1. **多个 per-user TUN 共存**：每个用户一个 `listeners/tun`（`include-uid` + `proxy:` 直连，
   不查进程），两个用户同时跑，分流是否正确、会不会串台。
2. **域名是否真的下发给 per-user mihomo**：system mihomo 保留 fake-ip DNS，app 用域名访问，
   system mihomo 通过 `proxy:` 把**域名**（而非 IP / fake-ip）传给下游 per-user mihomo。

## 运行（需要 KVM）

```sh
nix flake check ./multiuser
```

## 拓扑

```
router (VM A)                                target (VM B)
┌─────────────────────────────────────┐     ┌──────────────┐
│ alice(1001) ── tun-alice ─┐         │     │              │
│ bob(1002)   ── tun-bob   ─┤         │     │ echo-server  │
│                           ▼         │     │  192.168.50.2 │
│ system mihomo (fake-ip DNS)         │     │  :9999 TCP+   │
│   tun-alice -> proxy socks5 :1080 ──┼────►│  UDP echo     │
│   tun-bob   -> proxy socks5 :1081 ──┼────►│              │
│      │                │             │     └──────▲───────┘
│  per-user alice  per-user bob       │            │
│  (mixed :1080)   (mixed :1081)      │            │
│   DIRECT         DIRECT             │            │
└─────────────────────────────────────┴────────────┘
```

## 关键设计

- system mihomo 的 DNS 用 `hosts` 静态映射 `echo-{alice,bob}.example.test` → `192.168.50.2`，
  走 fake-ip。app 的 DNS 查询（指向 `1.1.1.1`，非本机 → 走默认路由进 tun）被 `dns-hijack` 劫持，
  返回 fake-ip；app 连 fake-ip 时 system mihomo 反查出真实域名。
- 每个 per-user mihomo 的规则是 **`DOMAIN,echo-{自己}.example.test,DIRECT` + `MATCH,REJECT`**。
  因此：
  - 能连上 echo 就说明 per-user 拿到的**是域名而非 IP/fake-ip**（否则命中 REJECT）。
  - alice 访问 `echo-bob` 必须失败、反之亦然 —— 证明 `include-uid` 分流没串台。
- **不手动加 `ip rule uidrange`**：feasibility 测试为演示直连子网绕 tun 而手动加了一条；
  本测试要验证 mihomo 的 `include-uid` + `iproute2-rule-index` 能否**自动**生成
  `uid -> lookup table` 规则（真实笔记本场景依赖这点）。

## 判读预期

- 4 个断言全部满足：
  - `alice -> echo-alice.example.test`：`TCP_OK`
  - `alice -> echo-bob.example.test`：失败（REJECT）
  - `bob -> echo-bob.example.test`：`TCP_OK`
  - `bob -> echo-alice.example.test`：失败（REJECT）
- system mihomo 日志**没有** `could not get uid`（proxy 直连不查进程）。
- per-user mihomo 的 dial 日志里出现 `echo-alice.example.test` / `echo-bob.example.test` 域名。

## 尚未覆盖（如需再补）

- **UDP 域名下发**：socks5 的 UDP 域名转发比 TCP 复杂，本测试只测 TCP；UDP 走 IP 的场景
  feasibility 已单独验证过。
- **直连子网（局域网）绕 tun**：本测试把目标放在另一台 VM，per-user mihomo 自己 DIRECT 访问它，
  不在 alice/bob 的转发路径上，所以不触及 sing-tun「直连子网默认走 main」的问题。
  真实笔记本连局域网设备时是否要拉进 tun，是另一个独立议题。