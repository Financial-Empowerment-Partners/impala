//! Client source attribution for the pre-auth surface.
//!
//! Every unauthenticated throttle that keys on "who is calling" — the
//! per-source pre-auth rate limit, the `(identity, source)` lockouts, the
//! unverified-webhook limit — goes through [`client_source`], so there is
//! exactly one place that decides which IP a request is attributed to.
//!
//! The rule is **rightmost-minus-trusted-hops**, never leftmost. Every proxy
//! on the trusted path (the ALB, `TRUSTED_PROXY_HOPS = 1`) *appends* the
//! address it accepted the connection from to `X-Forwarded-For`, so the
//! entry `TRUSTED_PROXY_HOPS` from the right is the first address a trusted
//! party wrote down; everything to its left is whatever the sender chose to
//! put there. Reading the leftmost entry — or `X-Real-Ip`, which nothing on
//! our path sets — hands the caller its own rate-limit bucket.
//!
//! With `TRUSTED_PROXY_HOPS = 0` (directly exposed, local docker-compose) the
//! header is ignored entirely and the TCP peer is the source, because a
//! direct client can write any `X-Forwarded-For` it likes.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::connect_info::ConnectInfo;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use log::error;
use sha2::{Digest, Sha256};

use crate::auth::AuthPolicy;
use crate::error::AppError;

/// The shared bucket for requests whose source cannot be attributed. Kept
/// deliberately narrow: legitimate traffic always arrives with a peer
/// address, so this only ever holds traffic that reached the bridge by an
/// unexpected path.
pub const UNKNOWN_SOURCE: &str = "unknown";

/// Attribute a request to a client IP.
///
/// - `trusted_hops == 0`: the socket peer, or [`UNKNOWN_SOURCE`] without one.
/// - `trusted_hops == N`: the N-th `X-Forwarded-For` entry counted from the
///   **right** (the address the outermost trusted proxy accepted the
///   connection from). With fewer than N entries the header was not written
///   by the expected proxy chain, so the socket peer is used instead.
///
/// The chosen candidate must parse as an IP address (a `host:port` form is
/// accepted and reduced to its host); anything else is [`UNKNOWN_SOURCE`], so
/// a sender cannot mint unlimited buckets by varying a garbage header.
/// IPv4-mapped IPv6 addresses are folded to IPv4 so a dual-stack listener
/// attributes `::ffff:203.0.113.7` and `203.0.113.7` to the same source.
pub fn client_source(headers: &HeaderMap, peer: Option<SocketAddr>, trusted_hops: u32) -> String {
    let peer_source = || {
        peer.map(|p| normalize_ip(p.ip()))
            .unwrap_or_else(|| UNKNOWN_SOURCE.to_string())
    };

    if trusted_hops == 0 {
        return peer_source();
    }

    let entries: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let hops = trusted_hops as usize;
    if entries.len() < hops {
        return peer_source();
    }

    match parse_ip(entries[entries.len() - hops]) {
        Some(ip) => normalize_ip(ip),
        None => UNKNOWN_SOURCE.to_string(),
    }
}

/// Parse an `X-Forwarded-For` entry: a bare IP, or `ip:port` /
/// `[v6]:port` as some proxies emit.
fn parse_ip(candidate: &str) -> Option<IpAddr> {
    candidate
        .parse::<IpAddr>()
        .ok()
        .or_else(|| candidate.parse::<SocketAddr>().ok().map(|s| s.ip()))
}

fn normalize_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        v4 => v4.to_string(),
    }
}

/// Short, fixed-width digest of a source for use inside Redis key names
/// (keeps IPv6 colons out of the key structure and bounds key length).
pub fn source_fingerprint(source: &str) -> String {
    let digest = hex::encode(Sha256::digest(source.as_bytes()));
    digest[..16].to_string()
}

/// Extractor form of [`client_source`] for pre-auth handlers.
///
/// Reads the socket peer recorded by `into_make_service_with_connect_info`
/// (absent → no peer, never an error) and the trusted-hop count from the
/// shared [`AuthPolicy`]. A missing policy is a wiring bug and fails closed:
/// attributing everything to one bucket would silently disable every
/// per-source control.
#[derive(Debug, Clone)]
pub struct ClientSource(pub String);

impl<S> FromRequestParts<S> for ClientSource
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let hops = parts
            .extensions
            .get::<Arc<AuthPolicy>>()
            .map(|policy| policy.trusted_proxy_hops)
            .ok_or_else(|| {
                error!(
                    "client_source: AuthPolicy extension missing — refusing to attribute source"
                );
                AppError::InternalError("Internal error".to_string())
            })?;
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0);
        Ok(ClientSource(client_source(&parts.headers, peer, hops)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn xff(value: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static(value));
        h
    }

    fn peer(s: &str) -> Option<SocketAddr> {
        Some(s.parse().unwrap())
    }

    /// The ALB shape: the sender wrote "spoofed", the ALB appended the real
    /// peer. One trusted hop must pick the ALB's entry, never the sender's.
    #[test]
    fn alb_shape_one_hop_takes_the_rightmost_entry() {
        let h = xff("203.0.113.7, 70.41.3.18");
        assert_eq!(client_source(&h, peer("10.0.0.5:443"), 1), "70.41.3.18");
        // A longer forged prefix changes nothing.
        let h = xff("1.1.1.1, 2.2.2.2, 3.3.3.3, 70.41.3.18");
        assert_eq!(client_source(&h, None, 1), "70.41.3.18");
    }

    #[test]
    fn zero_hops_ignores_the_header_and_uses_the_peer() {
        let h = xff("203.0.113.7, 70.41.3.18");
        assert_eq!(
            client_source(&h, peer("198.51.100.4:5000"), 0),
            "198.51.100.4"
        );
        assert_eq!(client_source(&h, None, 0), UNKNOWN_SOURCE);
    }

    #[test]
    fn two_hops_walks_left_from_the_right_edge() {
        // client -> proxy A -> proxy B -> bridge: A appended the client, B
        // appended A. Two trusted hops → the client.
        let h = xff("spoofed, 203.0.113.7, 10.1.1.1");
        assert_eq!(client_source(&h, None, 2), "203.0.113.7");
    }

    #[test]
    fn fewer_entries_than_hops_falls_back_to_the_peer() {
        let h = xff("203.0.113.7");
        assert_eq!(client_source(&h, peer("198.51.100.4:1"), 2), "198.51.100.4");
        assert_eq!(client_source(&h, None, 2), UNKNOWN_SOURCE);
        // No header at all behind one hop: the peer (the proxy itself, in
        // practice — better one narrow bucket than a sender-chosen one).
        assert_eq!(
            client_source(&HeaderMap::new(), peer("10.0.0.5:443"), 1),
            "10.0.0.5"
        );
    }

    #[test]
    fn garbage_in_the_trusted_slot_is_unknown_not_a_fresh_bucket() {
        assert_eq!(client_source(&xff("not-an-ip"), None, 1), UNKNOWN_SOURCE);
        assert_eq!(
            client_source(&xff("203.0.113.7, unknown"), peer("10.0.0.5:1"), 1),
            UNKNOWN_SOURCE
        );
        // An empty header value counts as no entries → peer fallback.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static(""));
        assert_eq!(client_source(&h, peer("10.0.0.5:1"), 1), "10.0.0.5");
    }

    #[test]
    fn x_real_ip_is_never_consulted() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static("198.51.100.4"));
        assert_eq!(client_source(&h, peer("10.0.0.5:1"), 1), "10.0.0.5");
        assert_eq!(client_source(&h, None, 1), UNKNOWN_SOURCE);
    }

    #[test]
    fn multiple_header_lines_are_read_in_order() {
        // A sender may split the header across lines; the proxy's append
        // still lands on the last one.
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_static("1.1.1.1"));
        h.append(
            "x-forwarded-for",
            HeaderValue::from_static("2.2.2.2, 70.41.3.18"),
        );
        assert_eq!(client_source(&h, None, 1), "70.41.3.18");
    }

    #[test]
    fn addresses_are_normalized() {
        // IPv4-mapped IPv6 folds to IPv4 (dual-stack listeners).
        assert_eq!(
            client_source(&xff("::ffff:203.0.113.7"), None, 1),
            "203.0.113.7"
        );
        assert_eq!(
            client_source(&HeaderMap::new(), peer("[::ffff:203.0.113.7]:443"), 0),
            "203.0.113.7"
        );
        // Plain IPv6 keeps its canonical form; host:port forms are reduced.
        assert_eq!(client_source(&xff("2001:db8::1"), None, 1), "2001:db8::1");
        assert_eq!(
            client_source(&xff("203.0.113.7:1234"), None, 1),
            "203.0.113.7"
        );
        assert_eq!(
            client_source(&xff("[2001:db8::1]:1234"), None, 1),
            "2001:db8::1"
        );
    }

    #[test]
    fn fingerprint_is_fixed_width_and_source_specific() {
        let a = source_fingerprint("203.0.113.7");
        let b = source_fingerprint("203.0.113.8");
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        assert_eq!(a, source_fingerprint("203.0.113.7"));
    }
}
