//! Where this device can be reached: the addresses an invitation names.
//!
//! An invitation has room for four. Another device may reach this one on
//! its home network, over a VPN such as Tailscale or WireGuard, or at a
//! global IPv6 address, so one of each comes before more of one kind. They
//! are hints like every address: the joiner pins the inviter's certificate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

/// Most addresses an invitation names.
pub const MAX_INVITATION_ADDRESSES: usize = 4;

/// Interfaces that join this computer to virtual machines and containers on
/// it, which no other device reaches.
const LOCAL_ONLY_INTERFACES: [&str; 6] = ["docker", "br-", "virbr", "veth", "bridge", "vmnet"];

/// Up to [`MAX_INVITATION_ADDRESSES`] addresses of this device with `port`,
/// best first: the one its route to the internet leaves from over IPv4,
/// then over IPv6, then those of its other interfaces. None is a loopback
/// or link-local address.
pub fn local_addresses(port: u16) -> Vec<String> {
    let mut found: Vec<IpAddr> = Vec::new();
    let mut add = |ip: IpAddr| {
        if reachable(ip) && !found.contains(&ip) {
            found.push(ip);
        }
    };
    if let Some(ip) = route_source(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 9))) {
        add(ip);
    }
    if let Some(ip) = route_source(SocketAddr::from((
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        9,
    ))) {
        add(ip);
    }
    let mut others: Vec<IpAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|interface| {
            !LOCAL_ONLY_INTERFACES
                .iter()
                .any(|prefix| interface.name.starts_with(prefix))
        })
        .map(|interface| interface.ip())
        .collect();
    // IPv4 before IPv6: a VPN's IPv4 address is the likelier to be reached.
    others.sort_by_key(|ip| ip.is_ipv6());
    for ip in others {
        add(ip);
    }
    found
        .into_iter()
        .take(MAX_INVITATION_ADDRESSES)
        .map(|ip| SocketAddr::new(ip, port).to_string())
        .collect()
}

/// The address a packet to `destination` would leave from. Connecting a UDP
/// socket sends nothing; it only selects a route.
fn route_source(destination: SocketAddr) -> Option<IpAddr> {
    let local: SocketAddr = match destination {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(local).ok()?;
    socket.connect(destination).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Whether another device could reach this address: not a loopback,
/// unspecified, multicast, or link-local one.
fn reachable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() || ip.is_multicast())
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip.to_ipv4_mapped().is_some())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_devices_addresses_are_ones_another_device_could_reach() {
        let addresses = local_addresses(47820);
        assert!(addresses.len() <= MAX_INVITATION_ADDRESSES);
        let mut seen = Vec::new();
        for address in &addresses {
            let address: SocketAddr = address.parse().unwrap();
            assert_eq!(address.port(), 47820);
            assert!(reachable(address.ip()), "{address}");
            assert!(!seen.contains(&address.ip()), "{address} twice");
            seen.push(address.ip());
        }
    }

    #[test]
    fn loopback_link_local_and_unspecified_addresses_are_left_out() {
        for left_out in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.10.20",
            "224.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
            "::ffff:192.168.1.2",
        ] {
            assert!(!reachable(left_out.parse().unwrap()), "{left_out}");
        }
        for kept in [
            "192.168.1.20",
            "10.0.0.5",
            "100.101.102.103",
            "2001:db8::5",
            "fd7a:115c:a1e0::1",
        ] {
            assert!(reachable(kept.parse().unwrap()), "{kept}");
        }
    }
}
