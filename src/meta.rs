//! Fetch IP ranges from JSON endpoints and seed them into nftables static sets.
//!
//! Generic over any URL + key list, expressed as `JsonList(...)` lines in
//! `allowed-domains.txt`.  Two key forms are supported:
//!
//! | Key form                  | JSON shape                                              |
//! |---------------------------|---------------------------------------------------------|
//! | `web`                     | `json["web"]` is `["cidr", ...]`                        |
//! | `prefixes[].ipv4Prefix`   | `json["prefixes"]` is `[{"ipv4Prefix": "cidr"}, ...]`  |
//!
//! Example endpoints:
//! - GitHub: `api.github.com/meta` — keys `web`, `api`, `git` (simple form)
//! - Google: `gstatic.com/ipranges/goog.json` — keys `prefixes[].ipv4Prefix`, `prefixes[].ipv6Prefix`
//! - AWS: `ip-ranges.amazonaws.com/ip-ranges.json` — keys `prefixes[].ip_prefix`, `ipv6_prefixes[].ipv6_prefix`

use anyhow::{Context, Result, bail};
use ipnet::{Ipv4Net, Ipv6Net};
use std::str::FromStr;

use crate::config::JsonIpListSpec;

/// Aggregated IP ranges from a JSON endpoint, split by address family.
pub struct IpRanges {
    pub v4: Vec<Ipv4Net>,
    pub v6: Vec<Ipv6Net>,
}

/// Return the top-level array key for a key spec.
/// `"web"` → `"web"`;  `"prefixes[].ipv4Prefix"` → `"prefixes"`.
fn array_key(key: &str) -> &str {
    key.split_once("[].").map(|(k, _)| k).unwrap_or(key)
}

/// Iterate over all CIDR strings described by `key` within `json`.
fn extract_cidrs<'a>(
    json: &'a serde_json::Value,
    key: &'a str,
) -> Box<dyn Iterator<Item = &'a str> + 'a> {
    if let Some((arr, field)) = key.split_once("[].") {
        Box::new(
            json[arr]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(move |obj| obj.get(field)?.as_str()),
        )
    } else {
        Box::new(
            json[key]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str()),
        )
    }
}

/// Fetch `spec.url`, extract CIDRs according to `spec.keys`, and return aggregated ranges.
///
/// Returns an error if the URL is unreachable, the response is not valid JSON, a required
/// top-level array is absent, or no usable CIDRs are found.
pub async fn fetch_ip_list(client: &reqwest::Client, spec: &JsonIpListSpec) -> Result<IpRanges> {
    let json: serde_json::Value = client
        .get(&spec.url)
        .send()
        .await
        .with_context(|| format!("fetching {}", spec.url))?
        .error_for_status()
        .with_context(|| format!("HTTP error from {}", spec.url))?
        .json()
        .await
        .with_context(|| format!("parsing JSON from {}", spec.url))?;

    for key in &spec.keys {
        let ak = array_key(key);
        if !json.get(ak).map(|v| v.is_array()).unwrap_or(false) {
            bail!("JSON response from {} missing array field `{ak}`", spec.url);
        }
    }

    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for key in &spec.keys {
        for cidr in extract_cidrs(&json, key) {
            if cidr.contains(':') {
                if let Ok(net) = Ipv6Net::from_str(cidr) {
                    v6.push(net);
                }
            } else if let Ok(net) = Ipv4Net::from_str(cidr) {
                v4.push(net);
            }
        }
    }

    if v4.is_empty() && v6.is_empty() {
        bail!("no usable IP ranges found at {}", spec.url);
    }

    Ok(IpRanges {
        v4: Ipv4Net::aggregate(&v4),
        v6: Ipv6Net::aggregate(&v6),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse_cidrs(json: serde_json::Value, key: &str) -> (Vec<Ipv4Net>, Vec<Ipv6Net>) {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for cidr in extract_cidrs(&json, key) {
            if cidr.contains(':') {
                if let Ok(net) = Ipv6Net::from_str(cidr) {
                    v6.push(net);
                }
            } else if let Ok(net) = Ipv4Net::from_str(cidr) {
                v4.push(net);
            }
        }
        (v4, v6)
    }

    #[test]
    fn simple_key_string_array() {
        let j = json!({"web": ["1.2.3.0/24", "2001:db8::/32"]});
        let (v4, v6) = parse_cidrs(j, "web");
        assert_eq!(v4.len(), 1);
        assert_eq!(v6.len(), 1);
    }

    #[test]
    fn path_key_ipv4_only() {
        let j = json!({"prefixes": [
            {"ipv4Prefix": "8.8.4.0/24"},
            {"ipv6Prefix": "2001:4860::/32"}
        ]});
        let (v4, v6) = parse_cidrs(j, "prefixes[].ipv4Prefix");
        assert_eq!(v4.len(), 1);
        assert_eq!(v6.len(), 0);
    }

    #[test]
    fn path_key_ipv6_only() {
        let j = json!({"prefixes": [
            {"ipv4Prefix": "8.8.4.0/24"},
            {"ipv6Prefix": "2001:4860::/32"}
        ]});
        let (v4, v6) = parse_cidrs(j, "prefixes[].ipv6Prefix");
        assert_eq!(v4.len(), 0);
        assert_eq!(v6.len(), 1);
    }

    #[test]
    fn path_key_missing_field_skipped() {
        // Objects without the requested field are silently skipped.
        let j = json!({"prefixes": [
            {"other": "not-a-cidr"},
            {"ip_prefix": "10.0.0.0/8"}
        ]});
        let (v4, _) = parse_cidrs(j, "prefixes[].ip_prefix");
        assert_eq!(v4.len(), 1);
    }

    #[test]
    fn aws_style_separate_v4_v6_arrays() {
        let j = json!({
            "prefixes": [{"ip_prefix": "3.4.12.4/32"}],
            "ipv6_prefixes": [{"ipv6_prefix": "2600:1f01::/48"}]
        });
        let (v4, _) = parse_cidrs(j.clone(), "prefixes[].ip_prefix");
        let (_, v6) = parse_cidrs(j, "ipv6_prefixes[].ipv6_prefix");
        assert_eq!(v4.len(), 1);
        assert_eq!(v6.len(), 1);
    }

    #[test]
    fn array_key_extraction() {
        assert_eq!(array_key("web"), "web");
        assert_eq!(array_key("prefixes[].ipv4Prefix"), "prefixes");
        assert_eq!(array_key("ipv6_prefixes[].ipv6_prefix"), "ipv6_prefixes");
    }
}
