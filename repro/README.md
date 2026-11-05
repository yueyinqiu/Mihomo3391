# 双栈 UDP UID 反查：三个独立场景

围绕 mihomo `resolveSocketByNetlink` 对「双栈 AF_INET6 socket 发出的 IPv4 包」反查不到 UID
（`process not found`）这一 bug，给出三个相互独立、复制粘贴即可复现的 flake。

| 场景 | 目录 | 跑法 | 预期 |
|---|---|---|---|
| 1. 正常无 bug | `1-normal/` | `nix flake check` | AF_INET socket 查到 `uid=1001` |
| 2. 双栈导致 bug | `2-dualstack-bug/` | `nix flake check` | 双栈 socket `process not found` |
| 3. 打 patch 后解决 | `3-patched/` | `nix flake check` | 双栈 socket 也查到 `uid=1001` |

三个目录**不互相引用**，各自是完整独立的 flake（自带 `flake.nix` + `machine.nix`，
场景 3 额外带 `fix-dualstack.patch`）。需要 KVM，无 KVM 请绕过 QEMU 跑（会走软件模拟非常慢）。

## 关键差异

- 场景 1 和 2 用的是 nixpkgs 原版 `mihomo`，区别只在测试脚本：场景 1 跑 `AF_INET` socket，
  场景 2 跑 `AF_INET6` 双栈 socket（`IPV6_V6ONLY=0`，发 `::ffff:1.1.1.1`）。
- 场景 3 通过 `pkgs.mihomo.overrideAttrs` 打了 `fix-dualstack.patch`，逻辑是：IPv4 查不到
  （`ErrNotFound`）时，用 IPv4-mapped 地址（`ip.As16()`）按 `AF_INET6` 再 dump 一次，
  从而匹配上双栈 socket。

## 判读

- 场景 1：日志 `[UDP] ... (python3.14, uid=1001) --> 1.1.1.1:9999`。
- 场景 2：日志 `[Process] find process error for 1.1.1.1: process not found`，随后 `[UDP]` 行没有 `uid=`。
- 场景 3：跑同样的双栈脚本，日志出现 `uid=1001`（修复生效）。