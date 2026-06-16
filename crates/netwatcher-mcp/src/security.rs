use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;
use thiserror::Error;

pub const ALLOWED_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "tools/list",
    "tools/call",
];

pub const DEFAULT_SOURCES: &[&str] = &["zeek", "p0f", "fatt", "enriched"];

pub const DEFAULT_TOOLS: &[&str] = &[
    "search_events",
    "threat_summary",
    "analyze_ip",
    "list_sources",
];

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub max_request_bytes: usize,
    pub max_query_length: usize,
    pub max_results_limit: u64,
    pub max_hours: u64,
    pub max_response_bytes: usize,
    pub rate_limit_per_minute: u32,
    pub allowed_sources: HashSet<String>,
    pub enabled_tools: HashSet<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: 64 * 1024,
            max_query_length: 1024,
            max_results_limit: 100,
            max_hours: 168,
            max_response_bytes: 512 * 1024,
            rate_limit_per_minute: 120,
            allowed_sources: DEFAULT_SOURCES.iter().map(|s| (*s).to_string()).collect(),
            enabled_tools: DEFAULT_TOOLS.iter().map(|s| (*s).to_string()).collect(),
        }
    }
}

impl SecurityConfig {
    pub fn from_lists(
        allowed_sources: Option<Vec<String>>,
        enabled_tools: Option<Vec<String>>,
    ) -> Self {
        let mut config = Self::default();
        if let Some(sources) = allowed_sources {
            config.allowed_sources = sources.into_iter().collect();
        }
        if let Some(tools) = enabled_tools {
            config.enabled_tools = tools.into_iter().collect();
        }
        config
    }
}

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("{0}")]
    Validation(String),
    #[error("rate limit exceeded")]
    RateLimit,
    #[error("request exceeds maximum size ({max} bytes)")]
    RequestTooLarge { max: usize },
    #[error("method not allowed: {0}")]
    MethodNotAllowed(String),
    #[error("tool not enabled: {0}")]
    ToolDisabled(String),
}

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("{0}")]
    Validation(String),
    #[error("search backend unavailable")]
    Backend,
}

impl ToolError {
    pub fn client_message(&self) -> String {
        match self {
            Self::Validation(msg) => msg.clone(),
            Self::Backend => "Search backend unavailable".into(),
        }
    }
}

pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    state: Mutex<(Instant, u32)>,
}

impl RateLimiter {
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
            state: Mutex::new((Instant::now(), 0)),
        }
    }

    pub fn check(&self) -> Result<(), SecurityError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| SecurityError::Validation("rate limiter unavailable".into()))?;
        let (window_start, count) = &mut *guard;
        if window_start.elapsed() >= self.window {
            *window_start = Instant::now();
            *count = 0;
        }
        if *count >= self.max_per_window {
            return Err(SecurityError::RateLimit);
        }
        *count += 1;
        Ok(())
    }
}

pub fn validate_request_size(len: usize, max: usize) -> Result<(), SecurityError> {
    if len > max {
        return Err(SecurityError::RequestTooLarge { max });
    }
    Ok(())
}

pub fn validate_method(method: &str) -> Result<(), SecurityError> {
    if ALLOWED_METHODS.contains(&method) {
        Ok(())
    } else {
        Err(SecurityError::MethodNotAllowed(method.to_string()))
    }
}

pub fn validate_tool_enabled(tool: &str, enabled: &HashSet<String>) -> Result<(), SecurityError> {
    if enabled.contains(tool) {
        Ok(())
    } else {
        Err(SecurityError::ToolDisabled(tool.to_string()))
    }
}

pub fn validate_index_prefix(prefix: &str) -> Result<(), SecurityError> {
    if prefix.is_empty() || prefix.len() > 64 {
        return Err(SecurityError::Validation(
            "index prefix must be 1-64 characters".into(),
        ));
    }
    if !prefix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(SecurityError::Validation(
            "index prefix contains invalid characters".into(),
        ));
    }
    Ok(())
}

pub fn validate_source(source: &str, allowed: &HashSet<String>) -> Result<(), SecurityError> {
    if source.is_empty() || source.len() > 32 {
        return Err(SecurityError::Validation(
            "source must be 1-32 characters".into(),
        ));
    }
    if !source
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(SecurityError::Validation(
            "source contains invalid characters".into(),
        ));
    }
    if !allowed.contains(source) {
        return Err(SecurityError::Validation(format!(
            "source not allowed: {source}"
        )));
    }
    Ok(())
}

pub fn validate_query(query: &str, max_len: usize) -> Result<(), SecurityError> {
    if query.is_empty() {
        return Err(SecurityError::Validation("query must not be empty".into()));
    }
    if query.len() > max_len {
        return Err(SecurityError::Validation(format!(
            "query exceeds maximum length ({max_len} characters)"
        )));
    }
    if query.bytes().any(|b| b == 0 || b < 0x20 && b != b'\t') {
        return Err(SecurityError::Validation(
            "query contains invalid control characters".into(),
        ));
    }
    if contains_bidi_overrides(query) {
        return Err(SecurityError::Validation(
            "query contains disallowed unicode direction overrides".into(),
        ));
    }
    netwatcher_common::reject_lucene_injection_patterns(query)
        .map_err(SecurityError::Validation)?;
    Ok(())
}

pub fn validate_ip(ip: &str) -> Result<(), SecurityError> {
    if ip.len() > 45 {
        return Err(SecurityError::Validation("ip address too long".into()));
    }
    ip.parse::<std::net::IpAddr>()
        .map_err(|_| SecurityError::Validation("invalid ip address".into()))?;
    Ok(())
}

pub fn clamp_limit(limit: u64, max: u64) -> u64 {
    limit.min(max)
}

pub fn validate_hours(hours: u64, max: u64) -> Result<u64, SecurityError> {
    if hours == 0 {
        return Err(SecurityError::Validation(
            "hours must be greater than zero".into(),
        ));
    }
    if hours > max {
        return Err(SecurityError::Validation(format!(
            "hours exceeds maximum ({max})"
        )));
    }
    Ok(hours)
}

pub fn redact_args_for_audit(args: &Value) -> Value {
    match args {
        Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, value) in map {
                redacted.insert(key.clone(), redact_value(value));
            }
            Value::Object(redacted)
        }
        other => redact_value(other),
    }
}

fn redact_value(value: &Value) -> Value {
    match value {
        Value::String(s) => {
            if s.len() > 256 {
                Value::String(format!("{}… [truncated, len={}]", &s[..256], s.len()))
            } else {
                value.clone()
            }
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, item) in map {
                redacted.insert(key.clone(), redact_value(item));
            }
            Value::Object(redacted)
        }
        _ => value.clone(),
    }
}

pub fn sanitize_tool_response(text: String, max_bytes: usize) -> String {
    netwatcher_common::truncate_utf8(&text, max_bytes)
}

pub fn validate_search_args(args: &Value) -> Result<(), SecurityError> {
    netwatcher_common::reject_unknown_json_keys(args, &["query", "source", "limit"])
        .map_err(SecurityError::Validation)
}

pub fn validate_threat_summary_args(args: &Value) -> Result<(), SecurityError> {
    netwatcher_common::reject_unknown_json_keys(args, &["hours"]).map_err(SecurityError::Validation)
}

pub fn validate_analyze_ip_args(args: &Value) -> Result<(), SecurityError> {
    netwatcher_common::reject_unknown_json_keys(args, &["ip", "limit"])
        .map_err(SecurityError::Validation)
}

pub fn validate_list_sources_args(args: &Value) -> Result<(), SecurityError> {
    netwatcher_common::reject_unknown_json_keys(args, &[]).map_err(SecurityError::Validation)
}

pub fn tool_catalog_fingerprint(tools: &Value) -> String {
    let canonical = serde_json::to_string(tools).unwrap_or_default();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    canonical.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

pub fn log_audit(
    event: &str,
    method: Option<&str>,
    tool: Option<&str>,
    args: Option<&Value>,
    outcome: &str,
    duration_ms: Option<u64>,
    detail: Option<&str>,
) {
    let args_json = args
        .map(redact_args_for_audit)
        .and_then(|v| serde_json::to_string(&v).ok());
    tracing::info!(
        target: "mcp_audit",
        event = event,
        method = method.unwrap_or(""),
        tool = tool.unwrap_or(""),
        outcome = outcome,
        duration_ms = duration_ms.unwrap_or(0),
        detail = detail.unwrap_or(""),
        args = args_json.as_deref().unwrap_or(""),
        "mcp security audit"
    );
}

fn contains_bidi_overrides(text: &str) -> bool {
    text.chars().any(|c| {
        matches!(
            c,
            '\u{202A}'
                | '\u{202B}'
                | '\u{202C}'
                | '\u{202D}'
                | '\u{202E}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_ip() {
        assert!(validate_ip("not-an-ip").is_err());
        assert!(validate_ip("10.0.0.1; DROP").is_err());
    }

    #[test]
    fn accepts_valid_ip() {
        assert!(validate_ip("10.0.0.1").is_ok());
        assert!(validate_ip("2001:db8::1").is_ok());
    }

    #[test]
    fn rejects_oversized_query() {
        let query = "a".repeat(1025);
        assert!(validate_query(&query, 1024).is_err());
    }

    #[test]
    fn rejects_bidi_override_in_query() {
        assert!(validate_query("test\u{202E}payload", 1024).is_err());
    }

    #[test]
    fn rejects_lucene_field_specifiers_in_query() {
        assert!(validate_query("_index:secret", 1024).is_err());
    }

    #[test]
    fn rejects_unknown_tool_arguments() {
        let args = serde_json::json!({"query": "x", "extra": true});
        assert!(validate_search_args(&args).is_err());
    }

    #[test]
    fn rate_limiter_blocks_after_threshold() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        assert!(matches!(limiter.check(), Err(SecurityError::RateLimit)));
    }

    #[test]
    fn tool_catalog_fingerprint_is_stable() {
        let tools = serde_json::json!([{"name": "search_events"}]);
        assert_eq!(
            tool_catalog_fingerprint(&tools),
            tool_catalog_fingerprint(&tools)
        );
    }
}
