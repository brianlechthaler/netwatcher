use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::event::ThreatSeverity;

/// A single threat indicator from Emerging Threats or related feeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator: String,
    pub indicator_type: IndicatorType,
    pub categories: Vec<String>,
    pub severity: ThreatSeverity,
    pub description: String,
    pub feed: String,
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Ip,
    Cidr,
    Domain,
    Url,
}

/// In-memory threat intelligence store.
#[derive(Debug, Default)]
pub struct ThreatStore {
    ips: HashMap<String, ThreatIndicator>,
    cidrs: Vec<(String, ThreatIndicator)>,
}

impl ThreatStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, indicator: ThreatIndicator) {
        match indicator.indicator_type {
            IndicatorType::Ip => {
                self.ips.insert(indicator.indicator.clone(), indicator);
            }
            IndicatorType::Cidr => {
                self.cidrs.push((indicator.indicator.clone(), indicator));
            }
            IndicatorType::Domain | IndicatorType::Url => {
                self.ips.insert(indicator.indicator.clone(), indicator);
            }
        }
    }

    pub fn lookup_ip(&self, ip: &str) -> Option<&ThreatIndicator> {
        if let Some(ind) = self.ips.get(ip) {
            return Some(ind);
        }
        for (cidr, ind) in &self.cidrs {
            if ip_in_cidr(ip, cidr) {
                return Some(ind);
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.ips.len() + self.cidrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let Ok(prefix) = parts[1].parse::<u8>() else {
        return false;
    };
    let ip_octets = parse_ipv4(ip);
    let net_octets = parse_ipv4(parts[0]);
    if ip_octets.is_none() || net_octets.is_none() {
        return false;
    }
    let ip_octets = ip_octets.unwrap();
    let net_octets = net_octets.unwrap();
    let ip_bits = u32::from_be_bytes(ip_octets);
    let net_bits = u32::from_be_bytes(net_octets);
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    (ip_bits & mask) == (net_bits & mask)
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let octets: Vec<u8> = s.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() == 4 {
        Some([octets[0], octets[1], octets[2], octets[3]])
    } else {
        None
    }
}

/// Parse Emerging Threats compromised-ips.txt format.
pub fn parse_et_compromised_ips(content: &str) -> Vec<ThreatIndicator> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let ip = line.split_whitespace().next()?.to_string();
            Some(ThreatIndicator {
                indicator: ip.clone(),
                indicator_type: if ip.contains('/') {
                    IndicatorType::Cidr
                } else {
                    IndicatorType::Ip
                },
                categories: vec!["compromised".to_string()],
                severity: ThreatSeverity::High,
                description: "Emerging Threats compromised host".to_string(),
                feed: "emerging_threats_compromised".to_string(),
                rule_id: None,
            })
        })
        .collect()
}

/// Parse Snort/Suricata rules from ET botcc.rules for IP extraction.
pub fn parse_et_botcc_rules(content: &str) -> Vec<ThreatIndicator> {
    let mut indicators = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let sid = extract_sid(line);
        for ip in extract_ips_from_rule(line) {
            indicators.push(ThreatIndicator {
                indicator: ip.clone(),
                indicator_type: if ip.contains('/') {
                    IndicatorType::Cidr
                } else {
                    IndicatorType::Ip
                },
                categories: vec!["botnet".to_string(), "c2".to_string()],
                severity: ThreatSeverity::Critical,
                description: "Emerging Threats botnet C2".to_string(),
                feed: "emerging_threats_botcc".to_string(),
                rule_id: sid.clone(),
            });
        }
    }
    indicators
}

fn extract_sid(line: &str) -> Option<String> {
    line.split("sid:")
        .nth(1)?
        .split(';')
        .next()
        .map(|s| s.trim().to_string())
}

fn extract_ips_from_rule(line: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for token in line.split_whitespace() {
        if token.contains('.')
            && token
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        {
            let cleaned = token.trim_matches(|c| c == '[' || c == ']' || c == ',' || c == ';');
            if cleaned.contains('.') {
                ips.push(cleaned.to_string());
            }
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compromised_ips() {
        let content = "# comment\n1.2.3.4\n10.0.0.0/8\n";
        let indicators = parse_et_compromised_ips(content);
        assert_eq!(indicators.len(), 2);
    }

    #[test]
    fn cidr_match_works() {
        let mut store = ThreatStore::new();
        store.upsert(ThreatIndicator {
            indicator: "10.0.0.0/8".to_string(),
            indicator_type: IndicatorType::Cidr,
            categories: vec!["test".to_string()],
            severity: ThreatSeverity::High,
            description: "test".to_string(),
            feed: "test".to_string(),
            rule_id: None,
        });
        assert!(store.lookup_ip("10.1.2.3").is_some());
        assert!(store.lookup_ip("192.168.1.1").is_none());
    }

    #[test]
    fn direct_ip_lookup() {
        let mut store = ThreatStore::new();
        store.upsert(ThreatIndicator {
            indicator: "8.8.8.8".to_string(),
            indicator_type: IndicatorType::Ip,
            categories: vec!["dns".to_string()],
            severity: ThreatSeverity::Low,
            description: "test".to_string(),
            feed: "test".to_string(),
            rule_id: None,
        });
        assert_eq!(store.len(), 1);
        assert!(store.lookup_ip("8.8.8.8").is_some());
    }

    #[test]
    fn parses_botcc_rules() {
        let content = r#"alert ip $HOME_NET any -> 1.2.3.4 any (msg:"ET BOT"; sid:123; rev:1;)"#;
        let indicators = parse_et_botcc_rules(content);
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].indicator, "1.2.3.4");
        assert_eq!(indicators[0].rule_id.as_deref(), Some("123"));
    }

    #[test]
    fn skips_comments_and_empty_lines() {
        assert!(parse_et_compromised_ips("# only comment\n\n").is_empty());
    }

    #[test]
    fn invalid_cidr_does_not_match() {
        assert!(!ip_in_cidr("10.0.0.1", "not-a-cidr"));
        assert!(parse_ipv4("999.1.1.1").is_none());
    }
}
