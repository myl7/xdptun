#!/usr/bin/env python3

# Copyright (c) 2022 myl7
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import socket

addr = sys.argv[2]
host = addr.split(':')[0]
port = int(addr.split(':')[1])
soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def handle_client():
    msg = sys.argv[3]
    soc.sendto(msg.encode(), (host, port))


def handle_server():
    soc.bind((host, port))
    while True:
        info = soc.recvfrom(1024)
        print(info)


handler = sys.argv[1]
if handler == 'client':
    handle_client()
elif handler == 'server':
    handle_server()
else:
    print(f'invalid handler: {handler}')
    exit(1)
