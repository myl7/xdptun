<!-- Copyright (c) 2022 myl7 -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Benchmarks

## HTTP/1.0 over WireGuard over xdptun

### Environments

- Hostname: lenovo
  - Machine Type: Yoga Slim 7 Pro-14ACH5 Laptop (ideapad) - Type 82MS
    - [Spec](https://pcsupport.lenovo.com/us/en/products/laptops-and-netbooks/yoga-series/yoga-slim-7-pro-14ach5/82ms/82ms0000cd/pf2p5rrf)
  - Wired Network: 1000Mbps
  - OS: Arch Linux
  - Kernel Version: 5.16.14-arch1-1
- Hostname: pi
  - Machine Type: Raspberry Pi 3 Model B+
    - [Spec](https://www.raspberrypi.com/products/raspberry-pi-3-model-b-plus/)
  - Wired Network: 300Mbps over USB 2.0
  - OS: Raspberry Pi OS (64-bit)
    - Debian version: 11 (bullseye)
  - Kernel Version: 5.15.28-v8+
- Network: Connected locally over wired connection
  - Address: 192.168.1.0/24
  - Gateway: 192.168.1.1
  - IP Alloc: Static IP
    - lenovo: 192.168.1.1
    - pi: 192.168.1.2
- WireGuard: Version relies on Linux kernel version
  - Address: 192.168.2.0/24
  - Port: 8000
  - Config
    - lenovo: [`test/wg/peer1`](/test/wg/peer1)
      - Address: 192.168.2.1
    - pi: [`test/wg/peer2`](/test/wg/peer2)
      - Address: 192.168.2.2
- Python: lenovo version 3.10.2-1 in pacman
- cURL: pi version 7.74.0-1.3+deb11u1 in apt

### Steps

- Run `dd if=/dev/zero of=test bs=256M count=4` on lenovo to create a 1 GiB = 1073741824 bytes test file `test`
- Run `python3 -m http.server 8001` on lenovo to serve it on HTTP
- Run `curl <url> -O` on pi to fetch it
  - When url is http://192.168.1.1:8001/test , fetch over HTTP
  - When url is http://192.168.2.1:8001/test , fetch over HTTP over WireGuard
  - Load xpdtun (on original interfaces other than WireGuard interfaces), then fetch over HTTP over WireGuard over xdptun

Check tracing output to check if connection is fine, and then change to use release build

### Results

`Speed` means average download speed reported by cURL, and uses uint MiB/s

| Protocols                       | Speed 1 | Speed 2 | Speed 3 | Average Speed | CPU Usage |
| ------------------------------- | ------- | ------- | ------- | ------------- | --------- |
| HTTP                            | 15.1    | 14.8    | 15.0    | 15.0          | Medium    |
| HTTP over WireGuard             | 10.8    | 11.0    | 10.9    | 10.9          | High      |
| HTTP over WireGuard over xdptun | 9.80    | 9.80    | 9.80    | 9.80          | Higher    |

Though WireGuard is known as lightweight VPN, for Raspberry Pi 3 Model B+ it is still a heavy workload.
CPU is the bottleneck on some degree so we can not figure out the exact negative affect on throughput of xdptun so far.
We can in fact assert that xdptun increases CPU workload, but that is expected, and we can not even tell how much CPU workload is added exactly since in the instance HTTP over WireGuard over xdptun, CPU workload reaches device limit.
One good result is that even in the CPU-bottleneck situation, xdptun only causes about 10% throughput decreasing, which should be acceptable.
