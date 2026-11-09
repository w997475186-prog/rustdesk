#[cfg(not(target_os = "ios"))]
use hbb_common::whoami;
use hbb_common::{
    allow_err,
    anyhow::bail,
    config::Config,
    config::{self, RENDEZVOUS_PORT},
    log,
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{
        self,
        sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    },
    ResultType,
};

use serde::{Deserialize, Serialize};

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    path::PathBuf,
    time::Instant,
};

type Message = RendezvousMessage;

#[cfg(not(target_os = "ios"))]
pub(super) fn start_listening() -> ResultType<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], get_broadcast_port()));
    let socket = std::net::UdpSocket::bind(addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_millis(1000)))?;
    log::info!("lan discovery listener started");
    loop {
        let mut buf = [0; 2048];
        if let Ok((len, addr)) = socket.recv_from(&mut buf) {
            if let Ok(msg_in) = Message::parse_from_bytes(&buf[0..len]) {
                match msg_in.union {
                    Some(rendezvous_message::Union::PeerDiscovery(p)) => {
                        if p.cmd == "ping"
                            && config::option2bool(
                                "enable-lan-discovery",
                                &Config::get_option("enable-lan-discovery"),
                            )
                        {
                            let id = Config::get_id();
                            if p.id == id {
                                continue;
                            }
                            if let Some(self_addr) = get_ipaddr_by_peer(&addr) {
                                let mut msg_out = Message::new();
                                let mut hostname = crate::whoami_hostname();
                                // The default hostname is "localhost" which is a bit confusing
                                if hostname == "localhost" {
                                    hostname = "unknown".to_owned();
                                }
                                let peer = PeerDiscovery {
                                    cmd: "pong".to_owned(),
                                    mac: get_mac(&self_addr),
                                    id,
                                    hostname,
                                    username: crate::platform::get_active_username(),
                                    platform: whoami::platform().to_string(),
                                    ..Default::default()
                                };
                                msg_out.set_peer_discovery(peer);
                                socket.send_to(&msg_out.write_to_bytes()?, addr).ok();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn discover() -> ResultType<()> {
    let sockets = send_query()?;
    let rx = spawn_wait_responses(sockets);
    handle_received_peers(rx).await?;

    log::info!("discover ping done");
    Ok(())
}

pub fn send_wol(id: String) {
    let interfaces = default_net::get_interfaces();
    let mut sent = false;
    for peer in &config::LanPeers::load().peers {
        if peer.id == id {
            for (_, mac) in peer.ip_mac.iter() {
                if let Ok(mac_addr) = mac.parse() {
                    for interface in &interfaces {
                        for ipv4 in &interface.ipv4 {
                            // remove below mask check to avoid unexpected bug
                            // if (u32::from(ipv4.addr) & u32::from(ipv4.netmask)) == (u32::from(peer_ip) & u32::from(ipv4.netmask))
                            log::info!("Send wol to {mac_addr} of {}", ipv4.addr);
                            allow_err!(wol::send_wol(mac_addr, None, Some(IpAddr::V4(ipv4.addr))));
                            sent = true;
                        }
                    }
                }
            }
            break;
        }
    }
    // A discovered peer is gone from `LanPeers` once it is powered off, so the
    // discovery page is the only place that used to offer WOL. Fall back to the
    // wake-up info the user saved by hand for this id.
    if !sent {
        if let Some(target) = get_stored_wol_target(&id) {
            log::info!("Send wol to {} by saved wake-up info", target.mac);
            allow_err!(send_wol_to_mac(
                &target.mac,
                &target.broadcast_ip,
                target.port
            ));
        }
    }
}

/// UDP port of the magic packet. 9 is the discard port every NIC listens on, 7
/// is the echo port a few older NICs use instead.
pub const DEFAULT_WOL_PORT: u16 = 9;

/// A wake-up target saved by the user, persisted apart from `LanPeers` on
/// purpose: `LanPeers` is a discovery cache that drops a machine once it is
/// offline, while this has to survive exactly that.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WolTarget {
    /// RustDesk ID of the machine to wake, may be empty when the user only
    /// knows the MAC address.
    #[serde(default)]
    pub id: String,
    /// "AA:BB:CC:DD:EE:FF".
    #[serde(default)]
    pub mac: String,
    /// Empty means "every broadcast address of this machine", see
    /// `interface_broadcast_addrs()`.
    #[serde(default)]
    pub broadcast_ip: String,
    #[serde(default)]
    pub port: u16,
}

fn wol_targets_path() -> PathBuf {
    config::Config::path("wol_targets.json")
}

fn load_wol_targets() -> Vec<WolTarget> {
    let path = wol_targets_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => match serde_json::from_str(&s) {
            Ok(targets) => targets,
            Err(err) => {
                log::error!("Failed to parse {}: {}", path.display(), err);
                Vec::new()
            }
        },
        Err(_) => Vec::new(),
    }
}

fn store_wol_targets(targets: &[WolTarget]) {
    let path = wol_targets_path();
    if let Some(dir) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(dir) {
            log::error!("Failed to create {}: {}", dir.display(), err);
            return;
        }
    }
    match serde_json::to_string_pretty(targets) {
        Ok(s) => {
            if let Err(err) = std::fs::write(&path, s) {
                log::error!("Failed to write {}: {}", path.display(), err);
            }
        }
        Err(err) => log::error!("Failed to serialize wake-up info: {}", err),
    }
}

/// Normalize user input to "AA:BB:CC:DD:EE:FF" so that a MAC accepted once is
/// accepted everywhere, and reject garbage before it reaches the socket.
pub fn normalize_mac(mac: &str) -> ResultType<String> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        bail!("Invalid MAC address: {}", mac);
    }
    let mut parts = Vec::with_capacity(6);
    for i in (0..12).step_by(2) {
        parts.push(hex[i..i + 2].to_uppercase());
    }
    Ok(parts.join(":"))
}

fn mac_bytes(mac: &str) -> ResultType<Vec<u8>> {
    let mac = normalize_mac(mac)?;
    let mut bytes = Vec::with_capacity(6);
    for part in mac.split(':') {
        match u8::from_str_radix(part, 16) {
            Ok(b) => bytes.push(b),
            Err(err) => bail!("Invalid MAC address {}: {}", mac, err),
        }
    }
    Ok(bytes)
}

/// Broadcast address of every local IPv4 interface, paired with that interface's
/// own address. Binding the source address is what makes the packet leave through
/// the right NIC on a machine with several of them (VPN, Hyper-V, WSL, ...), a
/// socket bound to 0.0.0.0 would let the routing table decide instead.
fn interface_broadcast_addrs() -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let mut addrs: Vec<(Ipv4Addr, Ipv4Addr)> = Vec::new();
    for interface in default_net::get_interfaces() {
        for ipv4 in &interface.ipv4 {
            let addr = u32::from(ipv4.addr);
            let netmask = u32::from(ipv4.netmask);
            if ipv4.addr.is_loopback() || ipv4.addr.is_unspecified() || netmask == 0 {
                continue;
            }
            let broadcast = Ipv4Addr::from(addr | !netmask);
            if !addrs.iter().any(|(_, dest)| *dest == broadcast) {
                addrs.push((ipv4.addr, broadcast));
            }
        }
    }
    addrs
}

/// Send a magic packet to an explicit MAC address, broadcast address and port.
/// Unlike `send_wol()` this needs no discovery data, which is what makes waking
/// an arbitrary, long-offline machine possible.
pub fn send_wol_to_mac(mac: &str, broadcast_ip: &str, port: u16) -> ResultType<()> {
    let bytes = mac_bytes(mac)?;
    let mut packet = Vec::with_capacity(102);
    packet.extend_from_slice(&[0xff; 6]);
    for _ in 0..16 {
        packet.extend_from_slice(&bytes);
    }
    let port = if port == 0 { DEFAULT_WOL_PORT } else { port };
    let broadcast_ip = broadcast_ip.trim();
    // (source, destination) pairs.
    let mut dests: Vec<(Ipv4Addr, Ipv4Addr)> = Vec::new();
    if broadcast_ip.is_empty() {
        dests.extend(interface_broadcast_addrs());
    } else {
        match broadcast_ip.parse::<Ipv4Addr>() {
            Ok(ip) => dests.push((Ipv4Addr::UNSPECIFIED, ip)),
            Err(err) => bail!("Invalid broadcast address {}: {}", broadcast_ip, err),
        }
    }
    if dests.is_empty() {
        // A directed broadcast survives switches, 255.255.255.255 is dropped by
        // some of them, but it is still better than sending nothing.
        dests.push((Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST));
    }
    let mut sent = 0;
    for (src, dest) in &dests {
        let socket = match UdpSocket::bind(SocketAddr::from((*src, 0))) {
            Ok(s) => s,
            Err(err) => {
                log::error!("Failed to bind {:?} to send wol: {}", src, err);
                continue;
            }
        };
        if let Err(err) = socket.set_broadcast(true) {
            log::error!("Failed to enable broadcast to send wol: {}", err);
            continue;
        }
        match socket.send_to(&packet, SocketAddr::from((*dest, port))) {
            Ok(_) => {
                log::info!("Send wol to {} through {}:{}", mac, dest, port);
                sent += 1;
            }
            Err(err) => log::error!("Failed to send wol packet to {}:{}: {}", dest, port, err),
        }
    }
    if sent == 0 {
        bail!("Failed to send the magic packet");
    }
    Ok(())
}

/// Saved wake-up info for `id`, without consulting the discovery cache.
pub fn get_stored_wol_target(id: &str) -> Option<WolTarget> {
    if id.is_empty() {
        return None;
    }
    load_wol_targets().into_iter().find(|x| x.id == id)
}

/// Saved wake-up info for `id`. When the user has not saved anything, the MAC
/// seen during LAN discovery is used, so the discovery page keeps working
/// before and after this change.
pub fn get_wol_target(id: &str) -> Option<WolTarget> {
    if let Some(target) = get_stored_wol_target(id) {
        return Some(target);
    }
    for peer in &config::LanPeers::load().peers {
        if peer.id == id {
            if let Some(mac) = peer.ip_mac.values().find(|x| !x.is_empty()) {
                return Some(WolTarget {
                    id: id.to_owned(),
                    mac: normalize_mac(mac).unwrap_or_else(|_| mac.clone()),
                    broadcast_ip: "".to_owned(),
                    port: DEFAULT_WOL_PORT,
                });
            }
        }
    }
    None
}

pub fn set_wol_target(id: &str, mac: &str, broadcast_ip: &str, port: u16) -> ResultType<WolTarget> {
    let target = WolTarget {
        id: id.to_owned(),
        mac: normalize_mac(mac)?,
        broadcast_ip: broadcast_ip.trim().to_owned(),
        port: if port == 0 { DEFAULT_WOL_PORT } else { port },
    };
    let mut targets = load_wol_targets();
    targets.retain(|x| x.id != target.id);
    targets.push(target.clone());
    store_wol_targets(&targets);
    Ok(target)
}

pub fn remove_wol_target(id: &str) {
    let mut targets = load_wol_targets();
    let len = targets.len();
    targets.retain(|x| x.id != id);
    if targets.len() != len {
        store_wol_targets(&targets);
    }
}

#[inline]
fn get_broadcast_port() -> u16 {
    (RENDEZVOUS_PORT + 3) as _
}

fn get_mac(_ip: &IpAddr) -> String {
    #[cfg(not(target_os = "ios"))]
    if let Ok(mac) = get_mac_by_ip(_ip) {
        mac.to_string()
    } else {
        "".to_owned()
    }
    #[cfg(target_os = "ios")]
    "".to_owned()
}

#[cfg(not(target_os = "ios"))]
fn get_mac_by_ip(ip: &IpAddr) -> ResultType<String> {
    for interface in default_net::get_interfaces() {
        match ip {
            IpAddr::V4(local_ipv4) => {
                if interface.ipv4.iter().any(|x| x.addr == *local_ipv4) {
                    if let Some(mac_addr) = interface.mac_addr {
                        return Ok(mac_addr.address());
                    }
                }
            }
            IpAddr::V6(local_ipv6) => {
                if interface.ipv6.iter().any(|x| x.addr == *local_ipv6) {
                    if let Some(mac_addr) = interface.mac_addr {
                        return Ok(mac_addr.address());
                    }
                }
            }
        }
    }
    bail!("No interface found for ip: {:?}", ip);
}

// Mainly from https://github.com/shellrow/default-net/blob/cf7ca24e7e6e8e566ed32346c9cfddab3f47e2d6/src/interface/shared.rs#L4
fn get_ipaddr_by_peer<A: ToSocketAddrs>(peer: A) -> Option<IpAddr> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return None,
    };

    match socket.connect(peer) {
        Ok(()) => (),
        Err(_) => return None,
    };

    match socket.local_addr() {
        Ok(addr) => return Some(addr.ip()),
        Err(_) => return None,
    };
}

fn create_broadcast_sockets() -> Vec<UdpSocket> {
    let mut ipv4s = Vec::new();
    // TODO: maybe we should use a better way to get ipv4 addresses.
    // But currently, it's ok to use `[Ipv4Addr::UNSPECIFIED]` for discovery.
    // `default_net::get_interfaces()` causes undefined symbols error when `flutter build` on iOS simulator x86_64
    #[cfg(not(any(target_os = "ios")))]
    for interface in default_net::get_interfaces() {
        for ipv4 in &interface.ipv4 {
            ipv4s.push(ipv4.addr.clone());
        }
    }
    ipv4s.push(Ipv4Addr::UNSPECIFIED); // for robustness
    let mut sockets = Vec::new();
    for v4_addr in ipv4s {
        // removing v4_addr.is_private() check, https://github.com/rustdesk/rustdesk/issues/4663
        if let Ok(s) = UdpSocket::bind(SocketAddr::from((v4_addr, 0))) {
            if s.set_broadcast(true).is_ok() {
                sockets.push(s);
            }
        }
    }
    sockets
}

fn send_query() -> ResultType<Vec<UdpSocket>> {
    let sockets = create_broadcast_sockets();
    if sockets.is_empty() {
        bail!("Found no bindable ipv4 addresses");
    }

    let mut msg_out = Message::new();
    // We may not be able to get the mac address on mobile platforms.
    // So we need to use the id to avoid discovering ourselves.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let id = crate::ui_interface::get_id();
    // `crate::ui_interface::get_id()` will cause error:
    // `get_id()` uses async code with `current_thread`, which is not allowed in this context.
    //
    // No need to get id for desktop platforms.
    // We can use the mac address to identify the device.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let id = "".to_owned();
    let peer = PeerDiscovery {
        cmd: "ping".to_owned(),
        id,
        ..Default::default()
    };
    msg_out.set_peer_discovery(peer);
    let out = msg_out.write_to_bytes()?;
    let maddr = SocketAddr::from(([255, 255, 255, 255], get_broadcast_port()));
    for socket in &sockets {
        allow_err!(socket.send_to(&out, maddr));
    }
    log::info!("discover ping sent");
    Ok(sockets)
}

fn wait_response(
    socket: UdpSocket,
    timeout: Option<std::time::Duration>,
    tx: UnboundedSender<config::DiscoveryPeer>,
) -> ResultType<()> {
    let mut last_recv_time = Instant::now();

    let local_addr = socket.local_addr();
    let try_get_ip_by_peer = match local_addr.as_ref() {
        Err(..) => true,
        Ok(addr) => addr.ip().is_unspecified(),
    };
    let mut mac: Option<String> = None;

    socket.set_read_timeout(timeout)?;
    loop {
        let mut buf = [0; 2048];
        if let Ok((len, addr)) = socket.recv_from(&mut buf) {
            if let Ok(msg_in) = Message::parse_from_bytes(&buf[0..len]) {
                match msg_in.union {
                    Some(rendezvous_message::Union::PeerDiscovery(p)) => {
                        last_recv_time = Instant::now();
                        if p.cmd == "pong" {
                            if !crate::common::is_valid_untrusted_peer_id(&p.id) {
                                log::warn!(
                                    "Ignoring LAN discovery response from {} with invalid peer id",
                                    addr
                                );
                                continue;
                            }

                            let local_mac = if try_get_ip_by_peer {
                                if let Some(self_addr) = get_ipaddr_by_peer(&addr) {
                                    get_mac(&self_addr)
                                } else {
                                    "".to_owned()
                                }
                            } else {
                                match mac.as_ref() {
                                    Some(m) => m.clone(),
                                    None => {
                                        let m = if let Ok(local_addr) = local_addr {
                                            get_mac(&local_addr.ip())
                                        } else {
                                            "".to_owned()
                                        };
                                        mac = Some(m.clone());
                                        m
                                    }
                                }
                            };

                            if local_mac.is_empty() && p.mac.is_empty() || local_mac != p.mac {
                                allow_err!(tx.send(config::DiscoveryPeer {
                                    id: p.id.clone(),
                                    ip_mac: HashMap::from([
                                        (addr.ip().to_string(), p.mac.clone(),)
                                    ]),
                                    username: p.username.clone(),
                                    hostname: p.hostname.clone(),
                                    platform: p.platform.clone(),
                                    online: true,
                                }));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if last_recv_time.elapsed().as_millis() > 3_000 {
            break;
        }
    }
    Ok(())
}

fn spawn_wait_responses(sockets: Vec<UdpSocket>) -> UnboundedReceiver<config::DiscoveryPeer> {
    let (tx, rx) = unbounded_channel::<_>();
    for socket in sockets {
        let tx_clone = tx.clone();
        std::thread::spawn(move || {
            allow_err!(wait_response(
                socket,
                Some(std::time::Duration::from_millis(10)),
                tx_clone
            ));
        });
    }
    rx
}

async fn handle_received_peers(mut rx: UnboundedReceiver<config::DiscoveryPeer>) -> ResultType<()> {
    let mut peers = config::LanPeers::load().peers;
    peers.iter_mut().for_each(|peer| {
        peer.online = false;
    });

    let mut response_set = HashSet::new();
    let mut last_write_time: Option<Instant> = None;
    loop {
        tokio::select! {
            data = rx.recv() => match data {
                Some(mut peer) => {
                    let in_response_set = !response_set.insert(peer.id.clone());
                    if let Some(pos) = peers.iter().position(|x| x.is_same_peer(&peer) ) {
                        let peer1 = peers.remove(pos);
                        if in_response_set {
                            peer.ip_mac.extend(peer1.ip_mac);
                            peer.online = true;
                        }
                    }
                    peers.insert(0, peer);
                    if last_write_time.map(|t| t.elapsed().as_millis() > 300).unwrap_or(true)  {
                        config::LanPeers::store(&peers);
                        #[cfg(feature = "flutter")]
                        crate::flutter_ffi::main_load_lan_peers();
                        last_write_time = Some(Instant::now());
                    }
                }
                None => {
                    break
                }
            }
        }
    }

    config::LanPeers::store(&peers);
    #[cfg(feature = "flutter")]
    crate::flutter_ffi::main_load_lan_peers();
    Ok(())
}
