use clap::{Arg, ArgAction, Command, crate_version};
use fake_tcp::Stack;
use fake_tcp::packet::MAX_PACKET_LEN;
use log::{debug, error, info};
use phantun::fec::{self, Fec, FecConfig, HEADROOM};
use phantun::offload;
use phantun::utils::{assign_ipv6_address, connect_udp_reuseport, raise_fd_limit, shutdown_signal};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time;
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;

use phantun::UDP_TTL;

/// The UDP sockets of a new connection, one for each worker, connected to `remote_addr` from a
/// free port, and the address the remote end sees their datagrams coming from
async fn connect_udp(
    remote_addr: SocketAddr,
    count: usize,
) -> io::Result<(Vec<Arc<UdpSocket>>, SocketAddr)> {
    let local_addr = UdpSocket::bind(if remote_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?
    .local_addr()?;
    let socks = connect_udp_reuseport(local_addr, remote_addr, count).await?;
    let udp_local = socks[0].local_addr()?;
    Ok((socks, udp_local))
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

    let (tun_local6, tun_peer6) = if matches.get_flag("ipv4_only") {
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

    let tun = TunBuilder::new()
        .name(tun_name) // if name is empty, then it is set by kernel.
        .up() // or set it up manually using `sudo ip link set <tun-name> up`.
        .address(tun_local)
        .destination(tun_peer)
        .queues(num_cpus)
        .build()
        .unwrap();

    if let (Some(tun_local6), Some(tun_peer6)) = (tun_local6, tun_peer6) {
        assign_ipv6_address(tun[0].name(), tun_local6, tun_peer6);
    }

    info!("Created TUN device {}", tun[0].name());

    let offload = offload::start(&matches, tun[0].name(), fec_config.is_some(), None);

    //thread::sleep(time::Duration::from_secs(5));
    let mut stack = Stack::new(tun, tun_local, tun_local6);
    stack.listen(local_port);
    info!("Listening on {}", local_port);

    let main_offload = offload.clone();
    let main_loop = tokio::spawn(async move {
        let offload = main_offload;
        let mut buf_udp = [0u8; MAX_PACKET_LEN];
        let mut buf_tcp = [0u8; MAX_PACKET_LEN];

        loop {
            let mut sock = stack.accept().await;
            info!("New connection: {}", sock);

            // Dropping the connection, e.g. when out of file descriptors, keeps the others
            let (udp_socks, udp_local) = match connect_udp(remote_addr, num_cpus).await {
                Ok(socks) => socks,
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

            let packet_received = Arc::new(Notify::new());
            let quit = CancellationToken::new();
            let fec = fec_config.map(|c| Arc::new(Fec::new(c, sock.to_string())));
            offload::start_connection(offloaded.as_ref(), &sock, fec.as_ref(), &udp_socks[0]);

            if let Some(ref fec) = fec {
                let sock = sock.clone();
                let fec = fec.clone();
                let quit = quit.clone();

                tokio::spawn(async move {
                    tokio::select! {
                        _ = fec.run_flusher(&sock) => quit.cancel(),
                        _ = quit.cancelled() => {},
                    }
                });
            }
            for (i, udp_sock) in udp_socks.into_iter().enumerate() {
                let sock = sock.clone();
                let fec = fec.clone();
                let quit = quit.clone();
                let packet_received = packet_received.clone();

                tokio::spawn(async move {
                    let mut recovered = Vec::new();

                    loop {
                        tokio::select! {
                            Ok(size) = udp_sock.recv(&mut buf_udp[HEADROOM..]) => {
                                if fec::send_datagram(&sock, fec.as_deref(), &mut buf_udp[..HEADROOM + size]).await.is_none() {
                                    quit.cancel();
                                    return;
                                }

                                packet_received.notify_one();
                            },
                            res = sock.recv(&mut buf_tcp) => {
                                match res {
                                    Some(size) => {
                                        if size > 0
                                            && let Err(e) = fec::forward_to_udp(&udp_sock, fec.as_deref(), &buf_tcp[..size], &mut recovered).await {
                                                error!("Unable to send UDP packet to {}: {}, closing connection", remote_addr, e);
                                                quit.cancel();
                                                return;
                                            }
                                    },
                                    None => {
                                        quit.cancel();
                                        return;
                                    },
                                }

                                packet_received.notify_one();
                            },
                            _ = quit.cancelled() => {
                                debug!("worker {} terminated", i);
                                return;
                            },
                        };
                    }
                });
            }

            tokio::spawn(async move {
                // Packets converted by eBPF do not pass through here
                let mut offloaded_packets = offloaded.as_ref().map_or(0, |c| c.packets());
                loop {
                    let read_timeout = time::sleep(UDP_TTL);
                    let packet_received_fut = packet_received.notified();

                    tokio::select! {
                        _ = read_timeout => {
                            if let Some(ref c) = offloaded {
                                let packets = c.packets();
                                if packets != offloaded_packets {
                                    offloaded_packets = packets;
                                    continue;
                                }
                            }
                            info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);

                            quit.cancel();
                            return;
                        },
                        _ = quit.cancelled() => return,
                        _ = packet_received_fut => {},
                    }
                }
            });
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
