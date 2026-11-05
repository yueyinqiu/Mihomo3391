# Mihomo per-user TUN 测试（discussions#3391）

用 NixOS VM 验证两件事：

1. **方案可行性**：每个用户一个 TUN，`include-uid` 按 UID 分流 + `proxy:` 直接转发（不查进程）。
2. **双栈 bug 复现**：双栈 socket（`AF_INET6` + `IPV6_V6ONLY=0`）导致 UID 反查不到（`process not found`）。

## 运行方式

这是一个可复现的 flake，nixpkgs 由 `flake.lock` 锁定（`nixos-unstable`）。在**有 KVM** 的
机器上（本沙箱无 `/dev/kvm`，无法 boot）：

```sh
# 跑全部两个测试
nix flake check

# 或者单独跑某一个
nix build .#checks.x86_64-linux.feasibility --print-build-logs
nix build .#checks.x86_64-linux.dualStack   --print-build-logs
```

> flake 要求 `flake.nix` 和 `test/` 下的文件被 git 追踪，别人 `git clone` 后直接
> `nix flake check` 即可复现（首次会拉取并构建 nixos-unstable 的依赖，需要网络 + 时间）。

跑完把整个输出（尤其是 `ip rule`、`ip route table all`、mihomo 的 `journalctl` 日志、以及
`TCP_OK` / `UDP_OK` / `could not get uid` / `process not found` 这些关键行）贴回来。

## 拓扑（feasibility 测试）

```
router (VM A)                         target (VM B)
┌────────────────────────────────┐   ┌──────────────┐
│ alice(1001) ──┐                │   │              │
│               ▼                │   │ echo-server  │
│          tun-alice(198.19.0.1) │   │  192.168.50.2 │
│               │ (proxy: socks5 │   │  :9999  UDP+  │
│               │  127.0.0.1:1080)│   │  TCP echo    │
│               ▼                │   └──────▲───────┘
│ mihomo-user(1002) DIRECT ──────┼──────────┘
│   mixed in :1080               │    (eth1 192.168.50.0/24)
└────────────────────────────────┘
```

关键点：echo 目标在**另一个 VM** 上，保证 alice 的流量必须走默认路由，才会真正被
`include-uid` 拉进 TUN（如果把 echo 放本地地址，Linux 的 `local` 路由表优先级更高，流量会
直连、完全绕过 TUN，测不出效果）。

## 判读预期

- **feasibility**：`TCP_OK` + `UDP_OK` 都出现；系统 mihomo 日志**没有** `could not get uid`；
  最后停掉 `mihomo-user` 后 alice 的流量失败（证明确实走了 proxy 而不是直连）。
- **dualStack**：跑 A 脚本（`AF_INET`）日志里有 `uid=1001`；跑 B 脚本（`AF_INET6` 双栈发
  IPv4）日志里是 `process not found`（复现了 bug）。

## 文件

- `test/default.nix`：两个 `runNixOSTest` 的入口。
- `test/router.nix`：feasibility 的 mihomo 节点（系统级 `listeners/tun` + 用户 mihomo）。
- `test/target.nix`：feasibility 的 echo 目标节点。
- `test/dualstack.nix`：双栈复现的 mihomo 节点（顶层 `tun` + `find-process-mode: always`）。