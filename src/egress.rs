//! Conservative launch-time classification for non-model target egress.
//!
//! Rules are explicit operator input. Domain names are resolved once before
//! the target starts, and only exact socket-address matches are classified.
//! This deliberately does not infer intent from an address, certificate, or
//! shared CDN ownership.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt, io,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

pub const MAX_EGRESS_RULES: usize = 256;
pub const MAX_ENDPOINTS_PER_RULE: usize = 64;
pub const MAX_EGRESS_ENDPOINTS: usize = 4_096;
const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressClass {
    Auth,
    Telemetry,
    Update,
    Other,
}

impl EgressClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Telemetry => "telemetry",
            Self::Update => "update",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for EgressClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EgressClass {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auth" => Ok(Self::Auth),
            "telemetry" => Ok(Self::Telemetry),
            "update" => Ok(Self::Update),
            "other" => Ok(Self::Other),
            _ => Err("class must be one of auth, telemetry, update, or other".to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRuleSpec {
    pub class: EgressClass,
    pub host: String,
    pub port: u16,
}

impl fmt::Display for EgressRuleSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            write!(formatter, "{}=[{}]:{}", self.class, self.host, self.port)
        } else {
            write!(formatter, "{}={}:{}", self.class, self.host, self.port)
        }
    }
}

impl FromStr for EgressRuleSpec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > 1_024 || value.chars().any(char::is_control) {
            return Err("egress rule is too long or contains control characters".to_owned());
        }
        let (class, authority) = value
            .split_once('=')
            .ok_or_else(|| "egress rule must use CLASS=HOST:PORT".to_owned())?;
        if authority.is_empty() {
            return Err("egress rule host and port are required".to_owned());
        }
        let class = class.parse::<EgressClass>()?;
        let parsed = Url::parse(&format!("tcp://{authority}"))
            .map_err(|_| "egress rule must contain a valid HOST:PORT authority".to_owned())?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || !parsed.path().is_empty()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(
                "egress rule must not contain credentials, a path, a query, or a fragment"
                    .to_owned(),
            );
        }
        let host = match parsed
            .host()
            .ok_or_else(|| "egress rule host is required".to_owned())?
        {
            Host::Domain(domain) => domain.to_ascii_lowercase(),
            Host::Ipv4(address) => address.to_string(),
            Host::Ipv6(address) => address.to_string(),
        };
        if host.len() > 253 || host.contains('%') {
            return Err("egress rule host is too long or contains an IPv6 zone ID".to_owned());
        }
        let port = parsed
            .port()
            .ok_or_else(|| "egress rule requires an explicit port".to_owned())?;
        if port == 0 {
            return Err("egress rule port must be between 1 and 65535".to_owned());
        }
        Ok(Self { class, host, port })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointClassification {
    pub class: EgressClass,
    pub rule_ids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedEgressRule {
    pub rule_ids: Vec<u32>,
    pub class: EgressClass,
    pub host: String,
    pub port: u16,
    pub addresses: Vec<SocketAddr>,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct EgressResolution {
    pub rules: Vec<ResolvedEgressRule>,
    pub endpoints: HashMap<SocketAddr, EndpointClassification>,
}

impl EgressResolution {
    #[must_use]
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    #[must_use]
    pub fn was_truncated(&self) -> bool {
        self.rules.iter().any(|rule| rule.truncated)
    }
}

/// Resolve every configured rule under one global deadline. Any failed rule
/// aborts launch because silently ignoring an operator classification would
/// turn expected benign traffic back into ambiguous evidence.
pub async fn resolve(
    specs: &[EgressRuleSpec],
    model_endpoints: &[SocketAddr],
) -> io::Result<EgressResolution> {
    if specs.len() > MAX_EGRESS_RULES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("at most {MAX_EGRESS_RULES} egress rules are supported"),
        ));
    }
    if specs.is_empty() {
        return Ok(EgressResolution {
            rules: Vec::new(),
            endpoints: HashMap::new(),
        });
    }

    let mut selectors: BTreeMap<(String, u16), (EgressClass, Vec<u32>)> = BTreeMap::new();
    for (index, spec) in specs.iter().enumerate() {
        let rule_id = u32::try_from(index + 1).unwrap_or(u32::MAX);
        match selectors.entry((spec.host.clone(), spec.port)) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((spec.class, vec![rule_id]));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().0 != spec.class {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "egress selector {}:{} is assigned to both {} and {}",
                            spec.host,
                            spec.port,
                            entry.get().0,
                            spec.class
                        ),
                    ));
                }
                entry.get_mut().1.push(rule_id);
            }
        }
    }
    let pending: FuturesUnordered<_> = selectors
        .into_iter()
        .map(|((host, port), (class, rule_ids))| {
            resolve_one(EgressRuleSpec { class, host, port }, rule_ids)
        })
        .collect();
    let mut rules = tokio::time::timeout(RESOLUTION_TIMEOUT, collect_resolutions(pending))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "egress rule DNS resolution exceeded the global 5 second deadline",
            )
        })??;
    rules.sort_by_key(|rule| rule.rule_ids.first().copied().unwrap_or(u32::MAX));

    let model_endpoints: HashSet<_> = model_endpoints.iter().copied().collect();
    let mut endpoints: HashMap<SocketAddr, EndpointClassification> = HashMap::new();
    for rule in &rules {
        for address in &rule.addresses {
            if model_endpoints.contains(address) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "egress rules {:?} resolve to configured model endpoint {address}",
                        rule.rule_ids
                    ),
                ));
            }
            match endpoints.entry(*address) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(EndpointClassification {
                        class: rule.class,
                        rule_ids: rule.rule_ids.clone(),
                    });
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    if entry.get().class != rule.class {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "egress rules assign {address} to both {} and {}",
                                entry.get().class,
                                rule.class
                            ),
                        ));
                    }
                    entry.get_mut().rule_ids.extend_from_slice(&rule.rule_ids);
                    entry.get_mut().rule_ids.sort_unstable();
                    entry.get_mut().rule_ids.dedup();
                }
            }
            if endpoints.len() > MAX_EGRESS_ENDPOINTS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "egress rule resolution exceeded the {MAX_EGRESS_ENDPOINTS} endpoint limit"
                    ),
                ));
            }
        }
    }
    Ok(EgressResolution { rules, endpoints })
}

async fn collect_resolutions<F>(
    mut pending: FuturesUnordered<F>,
) -> io::Result<Vec<ResolvedEgressRule>>
where
    F: std::future::Future<Output = io::Result<ResolvedEgressRule>>,
{
    let mut rules = Vec::with_capacity(pending.len());
    while let Some(result) = pending.next().await {
        rules.push(result?);
    }
    Ok(rules)
}

async fn resolve_one(spec: EgressRuleSpec, rule_ids: Vec<u32>) -> io::Result<ResolvedEgressRule> {
    let mut unique = BTreeSet::new();
    let mut truncated = false;
    if let Ok(address) = spec.host.parse::<IpAddr>() {
        unique.insert(SocketAddr::new(address, spec.port));
    } else {
        let resolved = tokio::net::lookup_host((spec.host.as_str(), spec.port))
            .await
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("egress rules {rule_ids:?} DNS lookup failed"),
                )
            })?;
        for address in resolved {
            if unique.len() >= MAX_ENDPOINTS_PER_RULE && !unique.contains(&address) {
                truncated = true;
                continue;
            }
            unique.insert(address);
        }
    }
    if unique.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("egress rules {rule_ids:?} DNS lookup returned no addresses"),
        ));
    }
    let addresses = unique.into_iter().collect();
    Ok(ResolvedEgressRule {
        rule_ids,
        class: spec.class,
        host: spec.host,
        port: spec.port,
        addresses,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_canonicalizes_rules_without_accepting_url_features() {
        let rule: EgressRuleSpec = "auth=EXAMPLE.com:443".parse().unwrap();
        assert_eq!(rule.class, EgressClass::Auth);
        assert_eq!(rule.host, "example.com");
        assert_eq!(rule.port, 443);
        assert_eq!(rule.to_string(), "auth=example.com:443");

        let ipv6: EgressRuleSpec = "telemetry=[2001:db8::1]:4318".parse().unwrap();
        assert_eq!(ipv6.host, "2001:db8::1");
        assert_eq!(ipv6.to_string(), "telemetry=[2001:db8::1]:4318");

        for invalid in [
            "model=example.com:443",
            "auth=example.com",
            "auth=user@example.com:443",
            "auth=example.com:443/path",
            "auth=example.com:443/",
            "auth=example.com:443?secret=x",
            "auth=example.com:0",
        ] {
            assert!(invalid.parse::<EgressRuleSpec>().is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn resolves_literals_and_rejects_model_or_cross_class_collisions() {
        let specs = vec![
            "auth=192.0.2.10:443".parse().unwrap(),
            "auth=192.0.2.10:443".parse().unwrap(),
        ];
        let resolution = resolve(&specs, &[]).await.unwrap();
        let endpoint = "192.0.2.10:443".parse().unwrap();
        assert_eq!(resolution.endpoint_count(), 1);
        assert_eq!(resolution.endpoints[&endpoint].rule_ids, vec![1, 2]);

        let conflict = vec![
            "auth=192.0.2.10:443".parse().unwrap(),
            "telemetry=192.0.2.10:443".parse().unwrap(),
        ];
        assert!(resolve(&conflict, &[]).await.is_err());
        assert!(resolve(&specs[..1], &[endpoint]).await.is_err());
    }

    #[tokio::test]
    async fn resolution_is_bounded_before_network_work() {
        let rule: EgressRuleSpec = "other=192.0.2.1:443".parse().unwrap();
        let specs = vec![rule; MAX_EGRESS_RULES + 1];
        let error = resolve(&specs, &[]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
