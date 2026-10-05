# veepin

纯 Go 用户态 VPN，提供命令行客户端、服务端和可嵌入的 Go 接口，无需 CGO。TUN/TAP 数据通路与路由配置主要面向 Linux。

本仓库为 [wanan9999/veepin](https://github.com/wanan9999/veepin)，基于 [xen0bit/veepin](https://github.com/xen0bit/veepin)，保留原作者版权与 [MIT 许可证](LICENSE)。Go 模块为 `github.com/wanan9999/veepin`；NetworkManager 子模块为 `github.com/wanan9999/veepin/nm`。

[功能](#功能) · [构建](#构建) · [运行](#运行) · [库集成](#库集成) · [验证与限制](#验证与限制)

<a id="what-it-does"></a>

## 功能

支持以下 16 种协议的客户端和服务端，具体认证方式、参数与限制见各协议指南。

<!-- 保留英文计数供现有注册表一致性测试校验：sixteen production protocols; TOY is the seventeenth registered protocol. Ten protocols therefore carry a pq- variant; Six protocols have **no** pq- variant. -->

| 协议 | 使用指南 | 协议 | 使用指南 |
|---|---|---|---|
| IKEv2/ESP | [IKEv2](doc/usage/ikev2.md) | WireGuard | [WireGuard](doc/usage/wireguard.md) |
| OpenVPN | [OpenVPN](doc/usage/openvpn.md) | SSTP | [SSTP](doc/usage/sstp.md) |
| SSH | [SSH](doc/usage/ssh.md) | L2TP/IPsec | [L2TP](doc/usage/l2tp.md) |
| L2TPv3 | [L2TPv3](doc/usage/l2tpv3.md) | AnyConnect | [AnyConnect](doc/usage/anyconnect.md) |
| Nebula | [Nebula](doc/usage/nebula.md) | MASQUE | [MASQUE](doc/usage/masque.md) |
| Fortinet | [Fortinet](doc/usage/fortinet.md) | GlobalProtect | [GlobalProtect](doc/usage/gp.md) |
| Cisco IPsec | [Cisco IPsec](doc/usage/cisco.md) | Ivanti Connect Secure | [Ivanti](doc/usage/pulse.md) |
| SoftEther VPN | [SoftEther](doc/usage/softether.md) | AmneziaWG | [AmneziaWG](doc/usage/amneziawg.md) |

<a id="the-example-protocol"></a>

`TOY` 仅为教学示例，不提供安全保护，不能用于实际 VPN 流量。其中 10 种协议提供强制后量子机制的 `pq-` 变体，另外 6 种没有此变体，要求与边界见 [后量子变体指南](doc/usage/pq-variants.md)。

<a id="install"></a>
<a id="build"></a>

## 构建

使用 `go.mod` 指定的 Go 版本：

```bash
git clone https://github.com/wanan9999/veepin.git
cd veepin
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o veepin ./cmd/veepin
```

已发布的产物见 [Releases](https://github.com/wanan9999/veepin/releases)。本分支的 APT 发布需要独立配置签名密钥与仓库，不能直接沿用上游签名身份。

<a id="run"></a>

## 运行

Linux TUN/TAP 模式需要 `/dev/net/tun` 和 `CAP_NET_ADMIN`，可使用 `sudo` 启动；自动配置 NAT 还需要相应系统网络工具。部署前确认监听端口、安全组与主机防火墙允许所需流量。

### L2TP/IPsec 服务端

将公网 IP、网卡名和示例凭据替换为实际值：

```bash
sudo ./veepin serve l2tp \
  -public 203.0.113.10 \
  -psk '替换为独立的预共享密钥' \
  -user vpnuser -pass '替换为账号密码' \
  -pool 10.20.0.0/24 -dns 1.1.1.1 \
  -tun tun0 -setup-nat -wan eth0
```

放行 UDP **500、4500**。本协议使用 NAT-T，L2TP 流量在 IPsec 内传输，不需要向公网开放裸 UDP 1701。`-setup-nat` 会修改主机网络配置，仅在需要通过主机转发上网时使用。

秘密参数支持对应的 `-<参数>-file` 形式，例如 `-psk-file`、`-pass-file`，可避免直接出现在进程参数中。完整配置见 [L2TP/IPsec 指南](doc/usage/l2tp.md)。

<a id="using-the-bundled-client"></a>

### 客户端

```bash
sudo ./veepin connect l2tp \
  -server 203.0.113.10 \
  -psk '替换为独立的预共享密钥' \
  -user vpnuser -pass '替换为账号密码'
```

通用入口为 `veepin serve <协议>` 和 `veepin connect <协议>`；参数以对应命令帮助及协议指南为准。持续运行与管理配置见 [服务管理](doc/usage/supervisor.md)、[管理面板](doc/usage/mgmt.md)。

<a id="architecture"></a>
<a id="embedding-the-client"></a>

## 库集成

L2TP 的 `PacketDeviceFactory(username, address, mtu)` 在认证与 IPCP 完成后创建独立会话设备；网络栈需使用传入的 MTU，不能固定为 1400。

通过公开协议包调用客户端或服务端，具体接口见包文档。`client.Dial` 返回会话及网络配置结果，不自动安装主机路由或地址，由调用方负责应用与清理。

L2TP 的 `ServerConfig.PacketDeviceFactory` 可为每个认证 PPP 会话提供独立 IPv4 数据设备，接入自有用户态网络栈，不必使用系统 TUN 或主机 NAT：

- `Write` 接收客户端数据包，`Read` 提供发回客户端的数据包。
- `Close` 必须解除阻塞并释放该会话资源。
- IPCP 完成后才接受数据，来源地址须匹配分配地址。
- `Server.KickUserSessions` 可关闭指定用户的设备及 VPN 会话。

结构与接口见 [架构说明](doc/architecture.md)、[L2TP 包](l2tp/)。

<a id="desktop-integration-networkmanager"></a>

NetworkManager 桌面集成单独位于 [nm/](nm/)，与根模块分别维护和构建。

<a id="testing"></a>
<a id="scope-and-limitations"></a>
<a id="cryptography"></a>
<a id="what-veepin-does-not-protect-against"></a>

## 验证与限制

```bash
go test ./...
go vet ./...
```

互通测试需要 Docker 等环境，步骤见 [测试说明](doc/testing.md)。单元测试、自身客户端互通及第三方客户端验收是不同层次；表中的结果不代表所有客户端、网络条件与长连接场景均已验证。

- L2TP/IPsec 使用 IKEv1 Main Mode + PSK、MS-CHAPv2 与 UDP 封装 ESP；不支持裸 ESP、证书认证、Aggressive Mode 或 Quick Mode PFS。
- 已包含 TunnelForge 0.7.4 所需 AES-128/SHA-1 算法兼容处理，并保留 AES-256。L2TP 支持续期与寿命限制处理，但 Windows、爱快的长期运行兼容性仍需真机验收。
- L2TP 控制消息按 RFC 2661 指数退避重传，探活复用可靠通道的失败判定，避免短时丢包过早清理连接。测试包含模拟时钟推进 25 小时的 IKE/ESP 换钥与回收；不等于真实公网连续 24 小时验收。
- 不同协议的身份认证、加密与重协商能力不同；安全边界见 [安全说明](doc/security.md)，不要把所有协议视为同一安全等级。
- 性能取决于算法、CPU、包长、客户端与网络。基准或 Docker 吞吐量不能直接等同于真实公网带宽。

<a id="interoperability-matrix"></a>

### 互通记录

以下两表由 CI 自动维护，保留原始测试名称及生成信息。`✓` 表示通过，`✗` 表示失败；`—` 及脚注表示未提供或不适用的测试方向，解释见 [测试说明](doc/testing.md)。

<details>
<summary>展开协议互通结果</summary>

<!-- livingreadme:interop:start -->
| Protocol   | veepin client ↔ real server | real client ↔ veepin server | veepin ↔ veepin (self) |
|------------|-----------------------------|-----------------------------|------------------------|
| IKEv2 | ✓ strongSwan (PSK + pubkey ECDSA/RSA, RFC 7383 frag, AES-GCM + ChaCha20, dual-stack, v6 underlay, ML-KEM-768, IP-TFS incl. constant-rate, recorded) + libreswan (incl. RFC 8229/9329 over TCP) | ✓ strongSwan (+ EAP-MSCHAPv2, pubkey RSA, RFC 7383 frag both ways, dual-stack, v6 underlay, TFC-padded, ML-KEM-768, IP-TFS) + libreswan (incl. RFC 8229/9329 over TCP) | ✓ (+ IP-TFS) |
| WireGuard | ✓ wireguard-go (+ IPv6 inner) | ✓ wireguard-go (+ padded, IPv6 inner, recorded) | ✓ |
| OpenVPN | ✓ `openvpn` (×4 variants) | ✓ `openvpn` (+ tls-auth, tls-crypt, padded, IPv6 inner) | ✓ |
| SSTP | ✓ SoftEther | ✓ `sstpc`/pppd (+ PPP-padded) | ✓ |
| SSH | ✓ `sshd` (PermitTunnel) | ✓ `ssh -w` | ✓ |
| L2TP/IPsec | ✓ strongSwan + xl2tpd | ✓ strongSwan + xl2tpd (+ PPP-padded) | ✓ |
| AnyConnect | ✓ ocserv | ✓ openconnect (TLS, DTLS, CSTP-padded) | ✓ |
| Nebula | ✓ `nebula` (lighthouse, shaped) | ✓ `nebula` (host) | ✓ (via lighthouse; relayed with the direct path blocked) |
| MASQUE-IP | ✓ aioquic CONNECT-IP | ✓ aioquic CONNECT-IP | ✓ |
| MASQUE-UDP | ✓ aioquic CONNECT-UDP | ✓ aioquic CONNECT-UDP | ✓ |
| Fortinet | —† | ✓ openconnect (TLS, DTLS, 2FA, PPP-padded) | ✓ (over DTLS) |
| GlobalProtect | —† | ✓ openconnect (SSL tunnel, ESP, padded) | ✓ (over ESP) |
| Cisco IPsec | ✓ strongSwan (aggressive + XAuth) | ✓ strongSwan (Mode-Config, TFC-padded) | ✓ |
| Ivanti Connect Secure | —† | ✓ openconnect (IF-T/TLS, ESP, padded) | ✓ (over ESP) |
| SoftEther VPN | ✓ SoftEther VPN Server (native SE-VPN, SecureNAT) | ✓ SoftEther VPN `vpnclient` | ✓ (layer 2, switched; shaped) |
| AmneziaWG | ✓ amneziawg-go | ✓ amneziawg-go | ✓ (H1-H4, S1-S4, junk) |
| L2TPv3 | ✓ Linux kernel (`ip l2tp`, 8-octet asymmetric cookies) | ✓ Linux kernel (`ip l2tp`) | ✓ (shaped) |
| pq-ikev2 | —† | ✓ strongSwan (ML-KEM-768 required, **and a classical initiator refused**) | ✓ |
| pq-openvpn | ✓ `openvpn` 2.6.14 (ML-DSA-65 mutual, ML-KEM-only groups) | ✓ `openvpn` 2.6.14 (ML-DSA-65 mutual, ML-KEM-only groups) | ✓ |
| pq-ssh | ✓ OpenSSH 10.0 requiring `mlkem768x25519-sha256` (kex only) | ✓ OpenSSH 10.0 requiring `mlkem768x25519-sha256` (kex only) | ✓ |
| pq-anyconnect | —† | —† | ✓ (over TLS: `-no-dtls` is forced) |
| pq-fortinet | —† | —† | ✓ (over TLS: `-no-dtls` is forced) |
| pq-gp | —† | —† | ✓ (over ESP) |
| pq-pulse | —† | —† | ✓ (over ESP) |
| pq-sstp | —† | —† | ✓ |
| pq-masque | —† | —† | ✓ |
| pq-softether | —† | —† | ✓ (layer 2, switched) |
| TOY* | ✓ independent Python peer | ✓ independent Python peer | ✓ |

_Generated by the `interop` workflow from `ce3f8f0` on 2026-10-05._
<!-- livingreadme:interop:end -->

</details>

<a id="benchmarks"></a>

<details>
<summary>展开互通吞吐量记录</summary>

<!-- livingreadme:interop-benchmark:start -->
| Protocol   | veepin client ↔ real server | real client ↔ veepin server | veepin ↔ veepin (self) |
|------------|----------------------------:|----------------------------:|-----------------------:|
| IKEv2 | 363 Mbit/s | 1.06 Gbit/s | 596 Mbit/s |
| WireGuard | 404 Mbit/s | 900 Mbit/s | 610 Mbit/s |
| OpenVPN | 607 Mbit/s | 984 Mbit/s | 887 Mbit/s |
| SSTP | — | 181 Mbit/s | 347 Mbit/s |
| SSH | 520 Mbit/s | 180 Mbit/s | 181 Mbit/s |
| L2TP/IPsec | 233 Mbit/s | 243 Mbit/s | 332 Mbit/s |
| AnyConnect | 462 Mbit/s | 486 Mbit/s | 311 Mbit/s |
| Nebula | 1.08 Gbit/s | 1.43 Gbit/s | 872 Mbit/s |
| MASQUE-IP | 22.6 Mbit/s | 39.2 Mbit/s | 315 Mbit/s |
| MASQUE-UDP | — | — | — |
| Fortinet | — | 483 Mbit/s | 313 Mbit/s |
| GlobalProtect | — | 693 Mbit/s | 606 Mbit/s |
| Cisco IPsec | 212 Mbit/s | 632 Mbit/s | 397 Mbit/s |
| Ivanti Connect Secure | — | 500 Mbit/s | 410 Mbit/s |
| SoftEther VPN | — | 1.06 Gbit/s | 797 Mbit/s |
| AmneziaWG | 787 Mbit/s | 1.26 Gbit/s | 861 Mbit/s |
| L2TPv3 | 408 Mbit/s | 1.17 Gbit/s | 423 Mbit/s |
| pq-ikev2 | — | 771 Mbit/s | 415 Mbit/s |
| pq-openvpn | 477 Mbit/s | 458 Mbit/s | 412 Mbit/s |
| pq-ssh | 643 Mbit/s | 236 Mbit/s | 245 Mbit/s |
| pq-anyconnect | — | — | 362 Mbit/s |
| pq-fortinet | — | — | 587 Mbit/s |
| pq-gp | — | — | 407 Mbit/s |
| pq-pulse | — | — | 414 Mbit/s |
| pq-sstp | — | — | 344 Mbit/s |
| pq-masque | — | — | 304 Mbit/s |
| pq-softether | — | — | 921 Mbit/s |
| TOY* | 37.8 Mbit/s | 38.6 Mbit/s | 658 Mbit/s |

_Generated by the `interop` workflow from `ce3f8f0` on 2026-10-05._
<!-- livingreadme:interop-benchmark:end -->

</details>

详细性能数据与测试方法见 [基准说明](doc/benchmarks.md)，可用 `./bench.sh` 或 `go test -bench . -benchmem ./...` 运行基准测试。

## windows注册表修改
```
# 1. 启用 NAT-T 封装（解决双 NAT 场景）
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" `
  -Name "AssumeUDPEncapsulationContextOnSendRule" -Value 2 -Type DWord -Force

# 2. 允许 RAS 使用 IPsec（L2TP/IPsec 前提）
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" `
  -Name "ProhibitIpSec" -Value 0 -Type DWord -Force

# 3. 允许较弱的加密算法（兼容旧版服务器）
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" `
  -Name "AllowL2TPWeakCrypto" -Value 1 -Type DWord -Force
```
