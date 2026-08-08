//! Egress policy for server-initiated HTTP requests (SSRF containment).
//!
//! Several endpoints let a caller register a URL that the bridge later fetches
//! itself: admin webhooks (`POST /admin/webhooks`), user notification webhooks
//! (`POST /notify`), and `cron_sync.callback_uri`. Those requests leave from
//! inside the deployment's network, so an unguarded fetch is a way to reach
//! the cloud metadata service, RDS/ElastiCache, or any internal service —
//! from a host that holds a KMS grant on the custodial seed key.
//!
//! [`validate_callback_url`](crate::validate::validate_callback_url) is the
//! registration-time gate; it gives a caller a clear 400 for an obviously bad
//! URL. It cannot be the only control, because it inspects a *string*: a
//! hostname that resolves to `169.254.169.254` passes it, and the address a
//! name resolves to can change between validation and connection (DNS
//! rebinding).
//!
//! [`EgressGuard`] is therefore the load-bearing control. Installed as the
//! reqwest DNS resolver, it vets the addresses that are *actually dialed*, on
//! every request and every redirect hop, so there is no window between the
//! check and the connection.

use log::warn;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// True when `ip` is not a public, routable internet address — i.e. an address
/// the bridge must never dial on behalf of a caller-supplied URL.
///
/// Covers loopback, private, link-local (which includes the cloud metadata
/// address `169.254.169.254`), carrier-grade NAT, unique-local, multicast and
/// reserved space, and unwraps the IPv6 forms that embed an IPv4 address —
/// `::ffff:169.254.169.254` reaches the same host as its IPv4 spelling and
/// must be judged by the same rules.
pub fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()                                 // 127.0.0.0/8
        || v4.is_private()                           // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()                        // 169.254/16, incl. metadata
        || v4.is_broadcast()                         // 255.255.255.255
        || v4.is_multicast()                         // 224.0.0.0/4
        || o[0] == 0                                 // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)   // 192.0.0.0/24 IETF assignments
        || (o[0] == 198 && (18..=19).contains(&o[1])) // 198.18/15 benchmarking
        || o[0] >= 240 // 240/4 reserved
}

fn is_blocked_v6(v6: &Ipv6Addr) -> bool {
    let seg = v6.segments();

    // ::ffff:a.b.c.d — IPv4-mapped, reaches the embedded IPv4 host.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_blocked_v4(&v4);
    }
    // ::a.b.c.d — deprecated IPv4-compatible form (also covers :: and ::1).
    if seg[0..6] == [0, 0, 0, 0, 0, 0] {
        return is_blocked_v4(&embedded_v4(seg[6], seg[7]));
    }
    // 64:ff9b::/96 — NAT64, embeds IPv4 in the low 32 bits.
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        return is_blocked_v4(&embedded_v4(seg[6], seg[7]));
    }
    // 2002::/16 — 6to4, embeds IPv4 in segments 1..3.
    if seg[0] == 0x2002 {
        return is_blocked_v4(&embedded_v4(seg[1], seg[2]));
    }

    v6.is_loopback()
        || v6.is_multicast()
        || v6.is_unspecified()
        || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
}

/// Rebuild the IPv4 address embedded in two IPv6 segments.
fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new(
        (hi >> 8) as u8,
        (hi & 0xff) as u8,
        (lo >> 8) as u8,
        (lo & 0xff) as u8,
    )
}

/// A reqwest DNS resolver that refuses to hand back any non-public address.
///
/// Install with `ClientBuilder::dns_resolver` on every client that fetches a
/// caller-supplied URL. Because reqwest resolves through this on each hop, it
/// covers redirects as well as the initial request, and because the check
/// happens at resolution time there is no check-to-connect gap for a rebinding
/// answer to slip through.
pub struct EgressGuard;

impl Resolve for EgressGuard {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // Port 0: reqwest substitutes the scheme's port (or the URL's).
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> BoxError {
                    format!("egress: DNS lookup for {host} failed: {e}").into()
                })?
                .collect();

            if resolved.is_empty() {
                return Err(format!("egress: {host} resolved to no addresses").into());
            }

            // Reject the whole answer if ANY address is internal rather than
            // filtering the bad ones out: a name that returns one public and
            // one private address is the shape of a rebinding attack, not a
            // host worth talking to.
            if let Some(blocked) = resolved.iter().find(|addr| is_blocked_ip(&addr.ip())) {
                warn!(
                    "egress: refusing to dial {} — resolves to non-public address {}",
                    host,
                    blocked.ip()
                );
                return Err(format!(
                    "egress: {host} resolves to non-public address {} — blocked by SSRF policy",
                    blocked.ip()
                )
                .into());
            }

            Ok(Box::new(resolved.into_iter()) as Addrs)
        })
    }
}

/// Build an HTTP client for fetching caller-supplied URLs.
///
/// Two properties matter and are easy to lose by writing a bare
/// `Client::builder()`: the egress guard above, and `redirect(Policy::none())`
/// — reqwest otherwise follows up to 10 redirects, which lets a URL that
/// passes every check 302 the request straight to an internal address without
/// the attacker needing any DNS control at all.
pub fn guarded_client(timeout_secs: u64) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(EgressGuard))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn blocked(s: &str) -> bool {
        is_blocked_ip(&IpAddr::from_str(s).expect("parseable address"))
    }

    #[test]
    fn blocks_loopback_and_private_v4() {
        for ip in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "0.0.0.0",
        ] {
            assert!(blocked(ip), "{ip} must be blocked");
        }
    }

    #[test]
    fn blocks_cloud_metadata_address() {
        // The single most valuable SSRF target on every major cloud.
        assert!(blocked("169.254.169.254"));
        assert!(blocked("169.254.0.1"));
    }

    #[test]
    fn blocks_cgnat_benchmark_and_reserved_v4() {
        for ip in [
            "100.64.0.1",      // CGNAT
            "100.127.255.255", // CGNAT upper bound
            "192.0.0.1",       // IETF protocol assignments
            "198.18.0.1",      // benchmarking
            "198.19.255.255",  // benchmarking upper bound
            "224.0.0.1",       // multicast
            "240.0.0.1",       // reserved
            "255.255.255.255", // broadcast
        ] {
            assert!(blocked(ip), "{ip} must be blocked");
        }
    }

    #[test]
    fn allows_public_v4() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.32.0.1",
            "100.63.255.255",
        ] {
            assert!(!blocked(ip), "{ip} must be allowed");
        }
    }

    #[test]
    fn blocks_internal_v6() {
        for ip in [
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "ff02::1",
        ] {
            assert!(blocked(ip), "{ip} must be blocked");
        }
    }

    #[test]
    fn allows_public_v6() {
        for ip in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            assert!(!blocked(ip), "{ip} must be allowed");
        }
    }

    /// The v6 spellings of an internal v4 address reach the same host, so they
    /// must not be a way around the v4 rules.
    #[test]
    fn blocks_v4_embedded_in_v6() {
        for ip in [
            "::ffff:169.254.169.254",   // IPv4-mapped metadata
            "::ffff:127.0.0.1",         // IPv4-mapped loopback
            "::ffff:10.0.0.1",          // IPv4-mapped private
            "::169.254.169.254",        // IPv4-compatible metadata
            "64:ff9b::169.254.169.254", // NAT64 metadata
            "64:ff9b::10.0.0.1",        // NAT64 private
        ] {
            assert!(blocked(ip), "{ip} must be blocked");
        }
        // 6to4 wrapping a private address: 2002:0a00:0001:: == 10.0.0.1
        assert!(blocked("2002:a00:1::"));
        // ...but 6to4 wrapping a public address stays allowed.
        assert!(!blocked("2002:808:808::"));
    }

    #[test]
    fn ipv4_mapped_public_is_allowed() {
        assert!(!blocked("::ffff:8.8.8.8"));
    }
}
