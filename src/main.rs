// Copyright (C) 2023 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

use clap::{Parser, ValueEnum};
use libbpf_rs::{TcHookBuilder, TC_EGRESS};

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
            let skel = egress::EgressSkelBuilder::default()
                .open()
                .unwrap()
                .load()
                .unwrap();
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
            let _fd = skel.progs().ingress_f().fd();

            todo!("ingress")
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
