# 双栈 UDP UID 反查：三个独立场景

围绕 mihomo `resolveSocketByNetlink` 对「双栈 AF_INET6 socket 发出的 IPv4 包」反查不到 UID
（`process not found`）这一 bug，给出三个相互独立、复制粘贴即可复现的 flake。

三个目录**不互相引用**，各自是完整独立的 flake（自带 `flake.nix` + `machine.nix` + `flake.lock`，
场景 3 额外带 `fix-dualstack.patch`）。三个 flake 结构完全对齐，唯一差异是：
`description`、脚本里的 socket 类型、以及断言方向（`succeed`/`fail` 互换）。

需要 KVM。

## 运行

```sh
nix flake check ./repro/1-normal
nix flake check ./repro/2-dualstack-bug
nix flake check ./repro/3-patched
```

每个场景都同时断言两件事（`succeed` 与 `fail` 互换），所以**三个 check 都应该通过**——
通过即表示「该场景的现象符合预期」，而不是靠 check 报错来表达结果。

| 场景 | socket | 断言 | 预期现象 |
|---|---|---|---|
| 1. 正常无 bug | `AF_INET` 单栈 | `succeed uid=1001` / `fail process not found` | 能查到 `uid=1001` |
| 2. 双栈导致 bug | `AF_INET6` 双栈（`IPV6_V6ONLY=0`） | `fail uid=1001` / `succeed process not found` | 查不到 uid，`process not found` |
| 3. 打 patch 后解决 | `AF_INET6` 双栈 | `succeed uid=1001` / `fail process not found` | 能查到 `uid=1001` |

## 关键差异

- 场景 1 和 2 用 nixpkgs 原版 `mihomo`，只有测试脚本不同：场景 1 跑 `AF_INET` socket，
  场景 2 跑 `AF_INET6` 双栈 socket（发 `::ffff:1.1.1.1`）。
- 场景 3 通过 `pkgs.mihomo.overrideAttrs` 打了 `fix-dualstack.patch`，逻辑是：IPv4 查不到
  （`ErrNotFound`）时，用 IPv4-mapped 地址（`ip.As16()`）按 `AF_INET6` 再 dump 一次，
  从而匹配上双栈 socket。

## 日志判读

- 场景 1：`[UDP] ... (python3.14, uid=1001) --> 1.1.1.1:9999`
- 场景 2：`[Process] find process error for 1.1.1.1: process not found`，随后 `[UDP]` 行没有 `uid=`
- 场景 3：同样的双栈脚本，日志出现 `uid=1001`（修复生效）
