<!-- Copyright (c) 2022 myl7 -->
<!-- SPDX-License-Identifier: CC-BY-NC-ND-4.0 -->

# xdptun:<br>基于 eBPF 的 UDP 包伪装方案

UDP packet obfuscation with eBPF

报告人：明宇龙

导师：华蓓

---

# 项目背景

UDP 现状

UDP 大流量应用在公网的层层 QoS 下表现糟糕，甚至是直接受到阻断

尤其是：劣质家宽、跨运营商访问、跨国访问

- UDP 不保证稳定传输且缺少拥塞控制机制，在网络压力大的情况下，由于缺乏反馈机制，中继节点倾向于直接丢包
- UDP 以往主要承载一些娱乐性和 P2P 流量，对服务质量不敏感，在 QoS 中受到策略的不公平对待
- UDP DRDoS 作为一种常见而强力的 DDoS 类型，进一步压缩了 UDP 大流量应用的生存空间

---

# 项目背景

上层协议设计

过去主要上层协议大多基于 TCP，甚至是进一步基于 HTTP，例如：

- 主导：HTTP（1.1 和 2）
- 文件传输：FTP
- 远程控制：SSH、VNC、RDP（Windows 7 及之前）
- 组网：BGP、OpenVPN
- 视频流：HLS、DASH
- 邮件：SMTP、POP、IMAP
- 直播推流：RMTP
- loT：MQTT

---

# 项目背景

上层协议设计

一部分原因有：

- TCP 的稳定传输简化了上层协议设计，保证了服务质量
- TCP/HTTP 支持广泛，便于上层协议推广
- TCP 特性更丰富，更能满足复杂上层协议的需求

---

# 项目背景

上层协议设计

而新一代上层协议开始逐渐发生变化，出现基于 UDP 的上层协议，例如：

- HTTP/3（= HTTP-over-QUIC，QUIC 基于 UDP）
  - 在 UDP 上实现了稳定传输并包含了强制的 TLS
  - 解决了队头阻塞问题
    - 多路复用与拥塞控制下队头丢包会影响后续包的发送
  - 支持：Google 主导开发，Cloudflare、Chrome 和 Firefox 已有部署，受 IETF 认可
- WireGuard
  - 轻量、安全、高性能、易配置的新一代 VPN 实现
  - 支持：Linux 5.6 合入主线

---

# 项目背景

UDP-over-TCP 现状

在对 UDP 不友好的此环境，为了保证这些新一代上层协议的正常使用和平滑过渡，此项目和众多现有项目一样实现了一套 UDP-over-TCP 方案

但现有 UDP-over-TCP 实现存在问题：

- 性能受限：简单地 send UDP via TCP 有冗余的内存分配、复制、连接管理，大致限于 100Mbps
  - 例如：GOST
- 无法复用 Linux 网络栈工具：wrap/unwrap 在用户态实现，无法复用功能丰富的 Linux 网络栈
  - 具体为 TC、Netfilter（Iptables）、Ipset 等工具

为了解决以上问题，我们选用了 eBPF 来实现一套 UDP-over-pseudo-TCP 方案，通过在 TC BPF 和 XDP 中插入 pseudo-TCP header 来实现 UDP-over-TCP

---

# 项目背景

eBPF

eBPF 允许在 Linux 内核中运行一段用户定义的沙箱代码，从而实现无需重新编译内核的内核态编程

eBPF 由旧的 BPF（cBPF）增强而来

Runtime：

- BPF Verifier：用形式化验证校验程序是否合法，保证 kernel 安全执行
- JIT：解释执行 BPF 指令，但同时保证性能
- Maps：可与用户态程序沟通
- Helper API：`<bpf/bpf_*.h>`

---

# 项目背景

eBPF

优点：

- 高性能
- 可以跳过特定 Linux 部分，从而最小化内存使用
- 高灵活度
- 有安全保证

名词声明：由于旧的 BPF 已增强为 eBPF，下文的 BPF 均指 eBPF，而旧的 BPF 则用 cBPF 指代

---

# 项目背景

eBPF

Linux 网络栈上的 BPF：

- XDP：ingress（入方向），位于网络栈最前端，先于 SKB 分配执行
- TC BPF：ingress/egress（入出双向），位于 TC 前后

均支持 offload，但仅极少数网卡支持

项目选择：XDP ingress、TC BPF egress

---

# eBPF 的实现细节

出方向

`int egress(struct __sk_buff *skb)`

```mermaid
flowchart LR
  S1[L2-L4 check] --> S2[bpf_skb_change_tail] --> S3[L2-L4 check] --> S4[copy 14 bytes with bpf_skb_store_bytes] --> S5[L2-L4 check] --> S6[L3/4 fields & checksum]
  subgraph now
    S1
  end
```

- `struct __sk_buff *skb` 提供 `void *data` 和 `void *data_end` 访问 frame 数据
- 从 `void *data` 开始将指针 cast 为 L2 `struct ethhdr *` -> L3 `struct iphdr *` -> L4 `struct udphdr *`，校验边界并依次移进指针，从而解析 header 并满足 BPF verifier 的要求
- 截留 L3 为 IP（此项目目前仅支持 IPv4）`ETH_P_IP` -> L4 为 UDP `IPPROTO_UDP` 的包，并利用编译选项做进一步 filter（例如过滤 源/目标 端口/地址）

---

# eBPF 的实现细节

出方向

```mermaid
flowchart LR
  S1[L2-L4 check] --> S2[bpf_skb_change_tail] --> S3[L2-L4 check] --> S4[copy 14 bytes with bpf_skb_store_bytes] --> S5[L2-L4 check] --> S6[L3/4 fields & checksum]
  subgraph now
    S2
    S3
  end
```

- 调用 `bpf_skb_change_tail` 扩大 SKB tail 空间以先 pad 原数据部分至至少 14 bytes（防止 overlapping），再在包末尾添加 14 bytes
- 此调用后所有 L2-L4 header 指针 invalid，需要重新进行 check
- check 过程中，利用 L3 IP header `total length` field 正向获取到原包末尾指针以在满足 BPF verifier 要求的情况下访问新添加的尾 14 bytes
  - BPF verifier 不允许从 `data_end` 开始移动指针，因为合法的指针范围是 `[data, data_end)` 不含 `data_end`，从 `data_end` 开始生成的指针是不合法的

---

# eBPF 的实现细节

出方向

```mermaid
flowchart LR
  S1[L2-L4 check] --> S2[bpf_skb_change_tail] --> S3[L2-L4 check] --> S4[copy 14 bytes with bpf_skb_store_bytes] --> S5[L2-L4 check] --> S6[L3/4 fields & checksum]
  subgraph now
    S4
    S5
  end
```

- 由于存在 SKB，需要利用 `bpf_skb_store_bytes` 进行数据移动
  - `memcpy`/`memmove` 在此处无法使用，否则无法通过 TC 中的 BPF verifier（后续 XDP 中可以使用）
- 移动 L4 UDP header 后 data 部分前 14 bytes 到包末尾新增的尾 14 bytes，为伪造 TCP header 留出足够空间
  - TCP header 无可选的 `Options` 和 `Padding`
- 此调用后所有 L2-L4 header 指针 invalid，需要重新进行 check

---

# eBPF 的实现细节

出方向

```mermaid
flowchart LR
  S1[L2-L4 check] --> S2[bpf_skb_change_tail] --> S3[L2-L4 check] --> S4[copy 14 bytes with bpf_skb_store_bytes] --> S5[L2-L4 check] --> S6[L3/4 fields & checksum]
  subgraph now
    S4
    S5
  end
```

<div style="display: flex; align-items: center; gap: 1em;">
<div>

```
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source      |   Destination   |
|      Port       |      Port       |
+--------+--------+--------+--------+
|     Length      |    Checksum     |
+--------+--------+--------+--------+
|            data octets
| (12 bytes started from here)
+---------------- ...
```

</div>
<div>-></div>
<div>

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Source Port (kept)       |   Destination Port (kept)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Sequence Number                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          data left                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

</div>
</div>

<style>
pre {
  font-size: 0.8rem;
}
</style>

---

# eBPF 的实现细节

出方向

```mermaid
flowchart LR
  S1[L2-L4 check] --> S2[bpf_skb_change_tail] --> S3[L2-L4 check] --> S4[copy 14 bytes with bpf_skb_store_bytes] --> S5[L2-L4 check] --> S6[L3/4 fields & checksum]
  subgraph now
    S6
  end
```

- 更新 L3 IP header `protocol`、`total length`、`header checksum`
- 更新 L4 TCP header `data offset`、`sequence number`
- Checksum
  - L3 checksum 总是由内核完成，此处需处理
  - L4 checksum offload 到 NIC card 完成
    - 原 UDP header checksum 由于需要 offload 到 NIC card 完成，此刻的值无意义，覆盖为 0
- 最后 `return TC_ACT_OK` 让包发出

---

# eBPF 的实现细节

入方向

`int ingress(struct xdp_md *ctx)`

```mermaid
flowchart LR
  S1[L2-L4 check] --> S2[copy 14 bytes back] --> S3[L3/4 fields & checksum] --> S4[bpf_xdp_adjust_tail]
  subgraph now
    S1
  end
```

- `struct xdp_md *ctx` 依然提供 `void *data` 和 `void *data_end` 访问 frame 数据，但是没有 SKB 的相关协议支持
- 校验边界、依次移进、解析 header、满足 verifier 要求的过程与出方向的大致相同
  - 额外校验 L3 IP header `total length` 和 L4 TCP header `data offset` 保证后续转换合法
- 截留 L3 为 IP（此项目目前仅支持 IPv4）`ETH_P_IP` -> L4 为 TCP `IPPROTO_TCP` 的包，并利用编译选项做进一步 filter（例如过滤 源/目标 端口/地址）

---

# eBPF 的实现细节

入方向

```mermaid
flowchart LR
  S1[L2-L4 check] --> S2[copy 14 bytes back] --> S3[L3/4 fields & checksum] --> S4[bpf_xdp_adjust_tail]
  subgraph now
    S2
  end
```

- 将 TCP header 指针 cast 为 UDP header，访问 `length` field 以计算 padding
- 类似与出方向，check 过程中，利用 L3 IP header `total length` field 正向获取到包尾 14 bytes 的头指针以在满足 BPF verifier 要求的情况下访问尾 14 bytes
- 复制包尾 14 bytes 的前 12 bytes 到 TCP header 尾 12 bytes，复制尾 2 bytes 到 TCP header sequence number 前 2 bytes 处

---

# eBPF 的实现细节

入方向

```mermaid
flowchart LR
  S1[L2-L4 check] --> S2[copy 14 bytes back] --> S3[L3/4 fields & checksum] --> S4[bpf_xdp_adjust_tail]
  subgraph now
    S2
  end
```

<div style="display: flex; align-items: center; gap: 1em;">
<div>

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Source Port (kept)       |   Destination Port (kept)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Acknowledgment Number (latter all are written)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          data left                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

</div>
<div>-></div>
<div>

```
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source      |   Destination   |
|      Port       |      Port       |
+--------+--------+--------+--------+
|     Length      |    Checksum     |
+--------+--------+--------+--------+
|          data octets ...
+---------------- ...
```

</div>
</div>

<style>
pre {
  font-size: 0.8rem;
}
</style>

---

# eBPF 的实现细节

入方向

```mermaid
flowchart LR
  S1[L2-L4 check] --> S2[copy 14 bytes back] --> S3[L3/4 fields & checksum] --> S4[bpf_xdp_adjust_tail]
  subgraph now
    S3
  end
```

- 更新 L3 IP header `protocol`、`total length`、`header checksum`
- 更新 L4 UDP header `checksum`
  - L4 TCP header 只保留 checksum，其余部分丢弃，利用 TCP checksum 恢复 UDP checksum

---

# eBPF 的实现细节

入方向

```mermaid
flowchart LR
  S1[L2-L4 check] --> S2[copy 14 bytes back] --> S3[L3/4 fields & checksum] --> S4[bpf_xdp_adjust_tail]
  subgraph now
    S4
  end
```

- `bpf_xdp_adjust_tail` 收缩 tail 空间以移除包末尾的 14 bytes + pad 的空间
  - 树莓派 Linux Kernel 中 NIC card driver 未设置 `frame_sz` field，会导致此调用失败，修改源码（安全地）注释此 check 即可
    - 树莓派**没有**官方性地支持 XDP
- 此调用后所有 L2-L4 header 指针 invalid，但已无需再使用这些指针
- 最后 `return XDP_PASS` 让包进入 Linux 网络栈

---

# eBPF 的实现细节

用户态程序

- xdp-project/libbpf-rs: Minimal and opinionated eBPF tooling for the Rust ecosystem
  - 完成可能的 map 持久化
  - Rust 方便整合其他框架（例如 clap 以实现 argument parsing）
- xdp-project/xdp-tools/xdp-loader: An XDP program loader
  - 相较于 iproute2，支持 BTF
    - clang -g 即可携带 BTF sections
    - 更详细的 symbols、Source annotated byte code，jited code and verifier log
- fallback: libbpf
  - C API，API 定义和用法比较艰涩

---

# eBPF 的实现细节

pseudo handshake

- 模拟 TCP SYN、SYN-ACK、ACK，打开与 CPU 数相同的“连接”数
- 利用 per-CPU map 记录当前 per-CPU sequence number，更新到 pseudo TCP header 中
  - 无锁
- pseudo TCP packet 不再被认为是 TCP 碎片，而是一个长连接的一部分
- 无视 ACK、拥塞控制等 TCP 功能

- 网络 eBPF 是 event-drive 的结构
- 需要在用户态利用 raw socket 来发送 pseudo SYN、SYN-ACK、ACK

---

# 性能测试

HTTP/1.0 over WireGuard over xdptun

环境：

```mermaid
flowchart LR
  S1[pi: Raspberry Pi 3B+] --- S2[local wired connection] --- S3[lenovo: My Laptop]
```

---

# 性能测试

HTTP/1.0 over WireGuard over xdptun

- 网络: Connected locally over wired connection
- Hostname: lenovo
  - 设备型号: Yoga Slim 7 Pro-14ACH5 Laptop (ideapad) - Type 82MS
  - 有线网络: 1000Mbps
  - OS: Arch Linux
  - 内核版本: 5.16.14-arch1-1
- Hostname: pi
  - 设备型号: Raspberry Pi 3 Model B+
  - 有线网络: 300Mbps over USB 2.0
  - OS: Raspberry Pi OS (64-bit)
    - Debian version: 11 (bullseye)
  - 内核版本: 5.15.28-v8+
  - 电源: 由 lenovo USB 供电

---

# 性能测试

HTTP/1.0 over WireGuard over xdptun

步骤：

- 生成一个 1 GiB = 1073741824 bytes 大小的测试大文件
- 利用 `python3 -m http.server` serve 此大文件
  - 使用 HTTP/1.0 即是受 `python3 -m http.server` 的限制
- 利用 cURL 下载此大文件
  - 利用 WireGuard bind 的不同 IP 测试经过 WireGuard 与否的状况
  - 加载 xpdtun 以测试是否进一步经过 xdptun
    - xdptun 加载到原 interface 而非 WireGuard 提供的 interface
- 先跟踪 log 判断 xdptun 是否被成功调用，确认后关闭 log 进行测试
  - 基于 `bpf_printk` 的 log 开销不小，需要排除其影响

---

# 性能测试

HTTP/1.0 over WireGuard over xdptun

结果：

- 表中 `Speed` 表示 cURL 报告的平均下载速率，单位为 MiB/s

| Protocols                           | Speed 1 | Speed 2 | Speed 3 | Average Speed | CPU Usage |
| ----------------------------------- | ------- | ------- | ------- | ------------- | --------- |
| HTTP/1.0                            | 15.1    | 14.8    | 15.0    | 15.0          | Medium    |
| HTTP/1.0 over WireGuard             | 10.8    | 11.0    | 10.9    | 10.9          | High      |
| HTTP/1.0 over WireGuard over xdptun | 9.80    | 9.80    | 9.80    | 9.80          | Higher    |

- WireGuard 对于树莓派而言太重，CPU 是瓶颈
- 在这种 CPU 为瓶颈的环境下，由于 xdptun 造成的额外 CPU 压力，throughput 会下降约 10%

---

# 性能测试

HTTP/3 over xdptun

环境：

- 同前
- 使用 Python 库 aioquic 实现 HTTP.3

步骤：

- 生成一个 1 GiB = 1073741824 bytes 大小的测试大文件
- 安装 Python 依赖
- 运行提供的 server 脚本 serve 此大文件
  - 由于 TLS 在 HTTP/3 是强制的（因为在 QUIC 中强制要求），需要使用提供的自签名证书
- 运行提供的 client 脚本下载此大文件
  - 加载 xpdtun 以测试是否经过 xdptun

---

# 性能测试

HTTP/3 over xdptun

结果：

- aioquic example 实现有性能问题，仅能达到约 600KB/s 且 CPU 占用不高

---

# 缺陷

协议部分

- 无法通过有 conntrack 检测的防火墙
  - 解决方案：模拟长连接、pseudo-handshake

---

# 缺陷

生态部分

- XDP、TC BPF 支持情况
  - 例如树莓派不保证 XDP 可用性、不支持 TC BPF
  - 依赖于 latest stable Linux kernel 的推广
    - 需要类似于 Arch Linux 的 rolling 发行版
    - Ubuntu、Debian 等需要手动进行内核更换且无法保证稳定性
  - XDP native mode 支持较少、offload 支持极稀少（目前仅一款 NIC），skb mode 下缺少性能优势
- BTF 支持情况
  - iproute2、tc 不支持
  - xdp-loader 支持，或是调用 libbpf API 进行 load 亦可

---

# 参考文献

Fast Packet Processing with eBPF and XDP: Concepts, Code, Challenges, and Applications

Limitations:

- Subset of C Language Libraries
- Non-static Global Variables
- Loops
- Limited Stack Space
- Complex Applications

---

# 参考文献

Fast Packet Processing with eBPF and XDP: Concepts, Code, Challenges, and Applications

Comparison:

- Programmable Data Planes
  - Run on edge
- High-speed Packet Processing
  - Bypass Linux kernel or not

---

# 附录

项目信息

GitHub Repo：[myl7/xdptun](https://github.com/myl7/xdptun)

- Code SPDX-License-Identifier: GPL-2.0-or-later
- Paper & Pre SPDX-License-Identifier: CC-BY-NC-ND-4.0

---
layout: center
---

# 谢谢！

<style>
h1 {
  font-size: 3.75rem !important;
}
</style>
