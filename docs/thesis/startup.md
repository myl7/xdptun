<!-- Copyright (c) 2022 myl7 -->
<!-- SPDX-License-Identifier: CC-BY-NC-ND-4.0 -->

# Startup Report

The report is to make the CS School allow me to start the project as my graduation project

## Content

### Basic Information

Project Chinese Title: 基于 XDP 的 UDP 包伪装方案

Project English Title: UDP packet obfuscation based on XDP

Supervisor 1 (in school): MASKED

Project Type: Other

Supervisor 2: NONE

### Project Description

公网环境下 QoS 的广泛使用导致了 UDP 协议表现不佳，并进一步影响了 HTTP/3 等基于 UDP 的新一代应用层协议的发展情况。
本项目旨在利用 Linux 内核主线新加入的高性能内核态网络包过滤及处理方案 XDP，截留并修改目标 UDP 包为类 TCP 包，从而在保持无连接的情况下将 UDP 流量伪装为 TCP 流量。
不同于传统的 UDP-over-TCP/HTTP 方案，本项目无需进行连接管理和承载协议的内存分配，能够以最小代价完成伪装工作，并能防止向 TCP 网络栈输送过多流量而导致拥塞和带宽限制。
完成伪装后，UDP 流量能够突破 QoS 限制，从而满足承载上层应用层协议的需求，保证基于 UDP 的新一代应用层协议能够在公网环境下正常工作。

### Main Subjects and Directions

主要研究学科：计算机网络、计算机系统、计算机安全
主要研究方向：eBPF、传输层协议栈、应用层协议栈、Linux 内核网络栈

### Work Plan and Time Arrangement

2022-02 - 2022-03-15：协议及标准阅读，制定具体的包处理方案，探索可能的定制优化方案
2022-03-15 - 2022-04-15：代码开发，性能测试，实际网络环境验证
2022-04-15 - 2022-05-15：对可能的定制优化方案进行开发，撰写论文，准备答辩

### Paper Overview

XDP 由于出现于 DPDK 等用户态网络栈解决方案之后且作为稳定特性时间尚短，探讨其不同方向实际应用的论文不多，主要集中在其原有的包过滤功能、高性能下的抗 DDoS 表现、以及 eBPF 在 XDP 中的具体应用细节等方面。
其中 Google 主导开发的 Cilium 项目是各论文的一个主要考察对象，其通过 eBPF 及 XDP 在 Linux 上实现了一套 per-process 的包过滤机制，进而扩大了 Linux 内核网络栈的应用面，并与当前的容器生态相兼容。
而 Cloudflare 则有一篇论文阐述了其利用 eBPF 及 XDP 的灵活性，整合了其原有的 DDoS 检测系统，在完成 DDoS 检测后即刻自动进行 DDoS 防御的具体解决方案。
除这些之外，亦有文章讨论在支持 XDP offload 的 NIC 上通过 offload 加速 eBPF 执行的具体实现方案与细节，甚至是综述整个 eBPF 系统的发展，归纳其在包括 XDP 在内的各个方面的具体发展情况及实际应用面。
