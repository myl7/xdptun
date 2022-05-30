<!-- Copyright (c) 2022 myl7 -->
<!-- SPDX-License-Identifier: CC-BY-NC-ND-4.0 -->

# xdptun:<br>基于 eBPF 的 UDP 包伪装方案

UDP packet obfuscation with eBPF

所在院系/答辩院系：计算机科学与技术系

报告人姓名：明宇龙

报告人学号：PB18111710

导师：华蓓 教授

日期：二〇二二年五月

---

# 目录

<div style="font-size: 2rem">

- 绪论
- 理论基础
- 设计方案
- 测试与分析
- 总结与展望

</div>

---

# 绪论

选题背景、研究意义、研究现状、项目工作

UDP 流量在公网中质量不佳，过去主要上层协议大多基于 TCP

而在新一代上层协议中开始出现基于 UDP 的上层协议，例如：HTTP/3、WireGuard

为了保证这些新一代上层协议的正常使用和平滑过渡，而出现的现有方案存在问题：

- 工业界中：UDP over TCP
  - 存在性能优化空间
  - 无法复用 Linux 网络栈工具
- 学术界中：协议解封装
  - 没有提供具体实现方案

为了解决以上问题，我们利用 eBPF 实现了一套 UDP over pseudo TCP 的方案，通过在 TC BPF 和 XDP 中插入 pseudo TCP header 来实现透明的、高性能的 UDP over TCP

---

# 理论基础

eBPF 和 XDP & TC BPF

eBPF 允许在 Linux 内核中运行一段用户定义的沙箱代码，从而实现无需重新编译内核的内核态编程

Runtime：BPF Verifier（形式化验证）、JIT（解释执行但保证性能）、Maps（持久化以及与用户态通信）、Helper API（`<bpf/bpf_*.h>`）

Linux 网络栈上的 BPF：

- XDP：ingress（入方向），位于网络栈最前端，先于 SKB 分配执行
- TC BPF：ingress/egress（入出双向），位于 TC 前后

本项目选择了 XDP ingress、TC BPF egress 作为接口

---

# 设计方案

出方向

<div style="display: flex; gap: 1em"><div>

![](/images/xdptun-flow-egress.drawio.svg)

图中 L2、L3、L4 分别为链路层、网络层、传输层的缩写，后同

</div><div>

TODO

</div></div>

---

# 设计方案

入方向

<div style="display: flex; gap: 1em"><div>

![](/images/xdptun-flow-ingress.drawio.svg)

</div><div>

TODO

</div></div>

---

# 测试与分析

功能测试和性能测试

- 功能测试
  - 环境：公网上两端连接进行文件下载
  - 结果：无法连通；WireShark 抓包显示确已转为 TCP 碎片，推测为带 conntrack 的流量过滤工具导致的
  - 在“总结与展望”部分我们额外提供了一套可行的解决方案
- 性能测试
  - 环境：本地中两端连接进行文件下载，一段为笔记本电脑，另一端为树莓派设备

---

# 测试与分析

性能测试

性能测试结果：

| Protocols                           | Speed 1 | Speed 2 | Speed 3 | Average Speed | CPU Usage |
| ----------------------------------- | ------- | ------- | ------- | ------------- | --------- |
| HTTP/1.0                            | 15.1    | 14.8    | 15.0    | 15.0          | Medium    |
| HTTP/1.0 over WireGuard             | 10.8    | 11.0    | 10.9    | 10.9          | High      |
| HTTP/1.0 over WireGuard over xdptun | 9.80    | 9.80    | 9.80    | 9.80          | Higher    |

结果数字均为平均下载速度，单位 MiB/s

性能测试结论：

- WireGuard 对于树莓派而言太重，CPU 是瓶颈
- 在这种 CPU 为瓶颈的环境下，由于 xdptun 造成的额外 CPU 压力，throughput 会下降约 10%

---

# 总结与展望

总结与展望

本项目 xdptun 作为一套 UDP over TCP 包伪装方案，能够突破传统 UDP over TCP 方案的局限，不仅仅依赖于 Linux API 提供的网络栈在用户态进行处理，而是借助 eBPF
直接在内核态、于 Linux 内核网络栈外进行数据包的伪装和解伪装

本项目依然存在可以改进和发展的空间：

- TCP 碎片伪装为 TCP 连接
  - 伪造开启 TCP 连接的 SYN、ACK-SYN、ACK
  - TCP 头部序列号字段改为连续值
  - Pre-core 无锁持久化
- eBPF 生态
  - Linux 内核版本
  - eBPF 周边设施，例如 daemonization

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
