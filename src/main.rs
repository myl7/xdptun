// Copyright (C) 2023 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

use std::net::Ipv4Addr;
use std::{fmt, ptr};

use clap::{Parser, ValueEnum};
use libbpf_rs::{libbpf_sys, TcHookBuilder, TC_EGRESS};

mod egress {
    include!(concat!(env!("OUT_DIR"), "/egress.skel.rs"));
}
mod ingress {
    include!(concat!(env!("OUT_DIR"), "/ingress.skel.rs"));
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let ifidx = nix::net::if_::if_nametoindex(cli.iface.as_str()).unwrap() as i32;
    match cli.direction {
        Direction::Egress => {
            let mut open_skel = egress::EgressSkelBuilder::default().open().unwrap();
            open_skel.rodata().peer_ip = cli.peer.into();
            let skel = open_skel.load().unwrap();
            let fd = skel.progs().egress_f().fd();

            let mut builder = TcHookBuilder::new();
            // Params are from libbpf/libbpf-rs /examples/tc_port_whitelist
            builder
                .fd(fd)
                .ifindex(ifidx)
                .replace(true)
                .handle(1)
                .priority(1);
            let mut hook = builder.hook(TC_EGRESS);

            match cli.act {
                Act::Attach => {
                    if let Err(e) = hook.attach() {
                        anyhow::bail!("Fail to attach: {}", e)
                    }
                }
                Act::Detach => {
                    if let Err(e) = hook.detach() {
                        anyhow::bail!("Fail to detach: {}", e)
                    }
                }
                Act::Query => match hook.query() {
                    Ok(id) => println!("Hook program ID: {}", id),
                    Err(e) => anyhow::bail!("No hook program: {}", e),
                },
            }
        }
        Direction::Ingress => {
            let skel = ingress::IngressSkelBuilder::default()
                .open()
                .unwrap()
                .load()
                .unwrap();
            let fd = skel.progs().ingress_f().fd();

            let in_mode = match cli.inmode {
                InMode::HW => libbpf_sys::XDP_FLAGS_HW_MODE,
                InMode::DRV => libbpf_sys::XDP_FLAGS_DRV_MODE,
                InMode::SKB => libbpf_sys::XDP_FLAGS_SKB_MODE,
            };
            {
                use libbpf_sys::*;
                match cli.act {
                    // TODO: libbpf-rs has not wrap XDP API, so we use libbpf-sys directly
                    // TODO: 3 modes
                    Act::Attach => unsafe {
                        // Safety: Only use ifidx, fd from out, which are all int
                        let flags = XDP_FLAGS_UPDATE_IF_NOEXIST | in_mode;
                        let err = bpf_xdp_attach(ifidx, fd, flags, ptr::null());
                        if err < 0 {
                            anyhow::bail!("Fail to attach: Code {}", err)
                        }
                    },
                    Act::Detach => unsafe {
                        let err = bpf_xdp_detach(ifidx, in_mode, ptr::null());
                        if err < 0 {
                            anyhow::bail!("Fail to detach: Code {}", err)
                        }
                    },
                    Act::Query => unsafe {
                        let mut id: u32 = 0;
                        let err = bpf_xdp_query_id(ifidx, in_mode as i32, &mut id);
                        if err < 0 {
                            anyhow::bail!("No hook program: Code {}", err)
                        }
                        if id == 0 {
                            anyhow::bail!("No hook program")
                        }
                        println!("Hook program ID: {}", id);
                    },
                };
            }
        }
    };
    Ok(())
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(after_help = "Copyright (C) 2022, 2023 myl7\nSPDX-License-Identifier: GPL-2.0-or-later")]
struct Cli {
    /// Traffic direction
    direction: Direction,
    /// Action
    act: Act,
    /// Network interface
    iface: String,

    /// Ingress XDP attach mode
    #[clap(short = 'm', long, default_value_t = InMode::DRV)]
    inmode: InMode,

    /// Peer IPv4 IP of which traffic will be filtered and modified
    #[clap(short, long)]
    peer: Ipv4Addr,
}
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Direction {
    Egress,
    Ingress,
}
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Act {
    Attach,
    Detach,
    Query,
}
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum InMode {
    /// Hardware offload (UNSUPPORTED currently)
    HW,
    /// Native mode relying on driver support
    DRV,
    /// Simulate after SKB allocation
    SKB,
}
impl fmt::Display for InMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InMode::HW => write!(f, "hw"),
            InMode::DRV => write!(f, "drv"),
            InMode::SKB => write!(f, "skb"),
        }
    }
}
