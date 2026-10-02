use clap::{Arg, ArgAction, Command, crate_version};
use fake_tcp::tun::Tun;
use fake_tcp::{Merge, Stack};
use log::{debug, error, info};
use phantun::fec::{self, Fec, FecConfig};
use phantun::forward::{self, forward};
use phantun::offload;
use phantun::utils::{assign_address, connect_udp, raise_fd_limit, shutdown_signal};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// The UDP socket of a new connection, connected to `remote_addr` from a free port, and the address
/// the remote end sees its datagrams coming from
async fn connect_udp_any(remote_addr: SocketAddr) -> io::Result<(UdpSocket, SocketAddr)> {
    let local_addr: SocketAddr = if remote_addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = connect_udp(local_addr, remote_addr, false).await?;
    let udp_local = sock.local_addr()?;
    Ok((sock, udp_local))
}

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();
    raise_fd_limit();

    let matches = Command::new("Phantun Server")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("PORT")
                .help("Sets the port where Phantun Server listens for incoming Phantun Client TCP connections")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Server forwards UDP packets to, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("tun")
                .long("tun")
                .required(false)
                .value_name("tunX")
                .help("Sets the Tun interface name, if absent, pick the next available name")
                .default_value("")
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface local address (O/S's end)")
                .default_value("192.168.201.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface destination (peer) address (Phantun Server's end). \
                       You will need to setup DNAT rules to this address in order for Phantun Server \
                       to accept TCP traffic from Phantun Client")
                .default_value("192.168.201.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Do not assign IPv6 addresses to Tun interface")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc9::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("fcc9::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \
                      first data packet to the client.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .args(fec::args())
        .args(offload::args())
        .args(forward::args())
        .get_matches();

    let local_port: u16 = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local port");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .next()
        .expect("unable to resolve remote host name");

    info!("Remote address is: {}", remote_addr);

    let tun_local: Ipv4Addr = matches
        .get_one::<String>("tun_local")
        .unwrap()
        .parse()
        .expect("bad local address for Tun interface");
    let tun_peer: Ipv4Addr = matches
        .get_one::<String>("tun_peer")
        .unwrap()
        .parse()
        .expect("bad peer address for Tun interface");

    let (tun_local6, tun_peer6): (Option<Ipv6Addr>, Option<Ipv6Addr>) =
        if matches.get_flag("ipv4_only") {
            (None, None)
        } else {
            (
                matches
                    .get_one::<String>("tun_local6")
                    .map(|v| v.parse().expect("bad local address for Tun interface")),
                matches
                    .get_one::<String>("tun_peer6")
                    .map(|v| v.parse().expect("bad peer address for Tun interface")),
            )
        };

    let tun_name = matches.get_one::<String>("tun").unwrap();
    let handshake_packet: Option<Vec<u8>> = matches
        .get_one::<String>("handshake_packet")
        .map(fs::read)
        .transpose()?;

    let fec_config = FecConfig::from_matches(&matches);
    if let Some(c) = fec_config {
        info!("FEC enabled: {c}");
    }

    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let gso = forward::gso(&matches);
    // if name is empty, then it is set by kernel.
    let tun = Tun::create(tun_name, num_cpus, gso).unwrap();
    assign_address(tun[0].name(), tun_local.into(), tun_peer.into());

    if let (Some(tun_local6), Some(tun_peer6)) = (tun_local6, tun_peer6) {
        assign_address(tun[0].name(), tun_local6.into(), tun_peer6.into());
    }

    info!("Created TUN device {}", tun[0].name());
    if tun[0].gro() {
        info!("Packets pass the Tun interface in batches");
    } else if gso {
        info!("Packets pass the Tun interface one by one, as the kernel does not support batches");
    }

    let offload = offload::start(&matches, tun[0].name(), fec_config.is_some(), None);

    //thread::sleep(time::Duration::from_secs(5));
    let merge = match (tun[0].gro(), &offload) {
        (false, _) => Merge::Never,
        (true, None) => Merge::Always,
        // the eBPF programs cannot convert merged packets, so only clients that merge themselves,
        // which likely lack eBPF, have them sent: they save more than the server loses
        (true, Some(_)) => Merge::WithPeer,
    };
    let mut stack = Stack::new(tun, tun_local, tun_local6, merge);
    stack.listen(local_port);
    info!("Listening on {}", local_port);

    let main_offload = offload.clone();
    let main_loop = tokio::spawn(async move {
        let offload = main_offload;
        loop {
            let mut sock = stack.accept().await;
            info!("New connection: {}", sock);

            // Dropping the connection, e.g. when out of file descriptors, keeps the others
            let (udp_sock, udp_local) = match connect_udp_any(remote_addr).await {
                Ok((sock, udp_local)) => (Arc::new(sock), udp_local),
                Err(e) => {
                    error!(
                        "Unable to connect UDP socket to {}: {}, closing connection",
                        remote_addr, e
                    );
                    continue;
                }
            };

            let offloaded = offload::register(offload.as_ref(), &mut sock, udp_local, remote_addr);
            let sock = Arc::new(sock);

            if let Some(ref p) = handshake_packet {
                if sock.send(p).await.is_none() {
                    error!("Failed to send handshake packet to remote, closing connection.");
                    continue;
                }

                debug!("Sent handshake packet to: {}", sock);
            }

            let fec = fec_config.map(|c| Arc::new(Fec::new(c, sock.to_string())));
            offload::start_connection(offloaded.as_ref(), &sock, fec.as_ref(), &udp_sock);

            tokio::spawn(forward(sock, udp_sock, remote_addr, fec, offloaded, gso));
        }
    });

    let result = tokio::select! {
        result = main_loop => result.unwrap(),
        _ = shutdown_signal() => {
            info!("Exiting");
            Ok(())
        },
    };
    if let Some(offload) = offload {
        offload.detach();
    }
    result
}
