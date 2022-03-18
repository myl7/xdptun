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
- Python: pi version 3.9.2
- cURL: lenovo version: 7.82.0

### Steps

- Run `dd if=/dev/zero of=bench bs=256M count=4` on pi to create a 1 GiB = 1073741824 bytes test file `bench`
- Run `python3 -m http.server 8001` on pi to serve it on HTTP
- Run `curl <url> -O` on lenovo to fetch it
  - When url is http://192.168.1.2:8001/bench , fetch over HTTP
  - When url is http://192.168.2.2:8001/bench , fetch over HTTP over WireGuard
  - Plus xpdtun is loaded, fetch over HTTP over WireGuard over xdptun

### Results

| Protocols                       | Average Speed | CPU usage on pi                               |
| ------------------------------- | ------------- | --------------------------------------------- |
| HTTP                            | 16.9MiB/s     | sometimes 1 core 70% - 80%, sometimes average |
| HTTP over WireGuard             | 9.64MiB/s     | 1 core full, others all about 40%             |
| HTTP over WireGuard over xdptun | 9.20MiB/s     | 1 core full, others all about 40%             |

On pi CPU workload caused by WireGuard should be the bottleneck, and there is no significant affect from xdptun
