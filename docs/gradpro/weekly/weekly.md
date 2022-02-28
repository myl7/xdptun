# 基于 XDP 的 UDP 包伪装方案

## 术语声明

下文中所有的 BPF 均指 eBPF，这是因为从 Linux 3.15 版本开始，eBPF 就已经被作为 BPF 的增强版本引入到了 Linux 内核中取代了原有的 BPF。[^1]

## BPF 及 XDP 的实现细节

Linux 内核提供了 API 用于挂载某个 BPF 二进制文件到相应的点位，从而在特定的时机对 NIC 所收到/发送的 L2 层包（packet）进行代码定义的处理。
在此项目中，我们使用了出方向（egress）上 TC 所提供的 egress 点位和入方向（ingress）上 XDP 所提供的点位，分别负责包装流量和解包流量。

在出方向上，我们使用 TC BPF，定义了 `int egress(struct __sk_buff *skb)` 这个函数进行处理。此函数首先从 L2 开始到 L4 判断是否是需要处理的数据包，否则不做修改。在确认了是需要修改的数据包后，此函数将调用 `bpf_skb_change_tail` 为 SKB 中的 data 区留下额外的 12 bytes 空间。为了满足 BPF verifier 的要求，在此调用之后程序需要重新从 L2 开始到 L4 获取数据包中每一层的 header 首地址，并借助 IP header 中的 total length 字段获取原 header 末尾的 offset 从而访问增加的额外 12 bytes 并通过 BPF verifier 的验证。此后正式进行包处理，此函数将把 UDP header 后 UDP data 区最前端的 12 bytes 移至末尾增加的 12 bytes 中，从而在 UDP header 处为伪造的 TCP header 空出足够的空间。最后更新 IP header 中各字段并重新为 L3 和 L4 进行 checksum，再将包发出。

在入方向上，我们使用了 XDP，定义了 `int ingress(struct xdp_md *ctx)` 这个函数进行处理。此函数同样首先从 L2 开始到 L4 判断是否是需要处理的数据包，否则不做修改。在确认了是需要修改的数据包后，此函数将借助 IP header 中的 total length 字段获取原 header 末尾的 12 bytes，并将这 12 bytes 复制到 20 bytes 长的伪造的 TCP header 的后 12 bytes 上，最后调用 `bpf_xdp_adjust_tail` 收缩数据包空间，再更新 IP header 中各字段并重新为 L3 和 L4 进行 checksum，又借助 `XDP_TX` 让此数据包重入 Linux 网络栈。

## 引用

[^1]: Marcos A. M. Vieira, Matheus S. Castanho, Racyus D. G. Pacífico, Elerson R. S. Santos, Eduardo P. M. Câmara Júnior, and Luiz F. M. Vieira. 2020. Fast Packet Processing with eBPF and XDP: Concepts, Code, Challenges, and Applications. *ACM Comput. Surv.* 53, 1, Article 16 (January 2021), 36 pages. DOI:https://doi.org/10.1145/3371038
