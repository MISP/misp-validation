//! Rust interpreter for the language-independent MISP attribute rule document.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{Duration, FixedOffset, NaiveDate, TimeZone};
use regex::{Regex, RegexBuilder};
use serde_json::{Map, Value};
use std::{fs, net::IpAddr, path::Path, str::FromStr, sync::OnceLock};
use thiserror::Error;
use url::Url;

/// A validation failure described by the attribute specification.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("{message} ({code})")]
pub struct ValidationError {
    pub code: String,
    pub message: String,
}

/// The normalized value and its validation status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationResult {
    pub valid: bool,
    pub value: String,
    pub error: Option<ValidationError>,
}

/// An invalid specification, unknown type, or unsupported rule operation.
#[derive(Debug, Error)]
pub enum RuleEngineError {
    #[error("failed to read specification file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse specification: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid regex pattern: {0}")]
    Regex(#[from] regex::Error),
    #[error("specification has no types object")]
    MissingTypes,
    #[error("unknown attribute type: {0}")]
    UnknownType(String),
    #[error("unknown hash definition: {0}")]
    UnknownHashDefinition(String),
    #[error("only hex hashes are supported by prototype")]
    UnsupportedHashEncoding,
    #[error("unsupported normalizer op: {0}")]
    UnsupportedNormalizer(String),
    #[error("unsupported validator op: {0}")]
    UnsupportedValidator(String),
    #[error("missing rule field: {0}")]
    MissingField(String),
    #[error("rule field is not text: {0}")]
    InvalidFieldType(String),
}

/// Interprets normalization and validation operations from a JSON rule specification.
pub struct RuleEngine {
    spec: Value,
}

impl RuleEngine {
    pub fn new(spec: Value) -> Result<Self, RuleEngineError> {
        let engine = Self { spec };
        engine.types()?;
        Ok(engine)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RuleEngineError> {
        Self::new(serde_json::from_str(&fs::read_to_string(path)?)?)
    }

    /// Create an engine using the attribute rules compiled into this crate.
    pub fn from_default_spec() -> Result<Self, RuleEngineError> {
        Self::new(serde_json::from_str(include_str!(
            "../../spec/attributes.json"
        ))?)
    }

    pub fn normalize(&self, type_name: &str, value: &str) -> Result<String, RuleEngineError> {
        let rule = self.type_rule(type_name)?;
        let value = self.apply_normalizers(value.to_owned(), self.default_normalizers())?;
        self.apply_normalizers(value, array(rule.get("normalize")))
    }

    pub fn validate(
        &self,
        type_name: &str,
        value: impl ToString,
    ) -> Result<ValidationResult, RuleEngineError> {
        let rule = self.type_rule(type_name)?;
        let normalized = self.apply_normalizers(value.to_string(), self.default_normalizers())?;
        let normalized = self.apply_normalizers(normalized, array(rule.get("normalize")))?;
        let (valid, value) = self.validate_rule(required(rule, "validate")?, normalized)?;
        let error = if valid {
            None
        } else {
            let error = rule.get("error");
            Some(ValidationError {
                code: text(error.and_then(|v| v.get("code")))
                    .unwrap_or("invalid_value")
                    .into(),
                message: text(error.and_then(|v| v.get("message")))
                    .unwrap_or("Invalid value.")
                    .into(),
            })
        };
        Ok(ValidationResult {
            valid,
            value,
            error,
        })
    }

    pub fn valid_types(&self, value: &str) -> Result<Vec<String>, RuleEngineError> {
        let mut result = Vec::new();
        for name in self.types()?.keys() {
            if self.validate(name, value)?.valid {
                result.push(name.clone());
            }
        }
        Ok(result)
    }

    fn types(&self) -> Result<&Map<String, Value>, RuleEngineError> {
        self.spec["types"]
            .as_object()
            .ok_or(RuleEngineError::MissingTypes)
    }

    fn type_rule(&self, name: &str) -> Result<&Value, RuleEngineError> {
        self.types()?
            .get(name)
            .ok_or_else(|| RuleEngineError::UnknownType(name.to_owned()))
    }

    fn default_normalizers(&self) -> &[Value] {
        array(self.spec.get("defaults").and_then(|v| v.get("normalize")))
    }

    fn apply_normalizers(
        &self,
        mut value: String,
        operations: &[Value],
    ) -> Result<String, RuleEngineError> {
        for operation in operations {
            let op = required_text(operation, "op")?;
            match op {
                "lowercase" => value = value.to_lowercase(),
                "uppercase" => value = value.to_uppercase(),
                "trim" => value = value.trim().to_owned(),
                "trim_chars" => {
                    value = value
                        .trim_matches(|c| {
                            required_text(operation, "characters")
                                .unwrap_or("")
                                .contains(c)
                        })
                        .to_owned()
                }
                "replace" => {
                    value = value.replace(
                        required_text(operation, "old")?,
                        required_text(operation, "new")?,
                    )
                }
                "replace_non_bmp" => {
                    let replacement = text(operation.get("replacement")).unwrap_or("?");
                    let mut output = String::new();
                    for character in value.chars() {
                        if character as u32 > 0xffff {
                            output.push_str(replacement);
                        } else {
                            output.push(character);
                        }
                    }
                    value = output;
                }
                "normalize_boolean" => {
                    value = match value.as_str() {
                        "true" => "1".into(),
                        "false" => "0".into(),
                        _ => value,
                    }
                }
                "regex_replace" => {
                    value = Regex::new(required_text(operation, "pattern")?)?
                        .replace_all(&value, text(operation.get("replacement")).unwrap_or(""))
                        .into_owned()
                }
                "normalize_mac" => {
                    let compact: Vec<char> = value
                        .to_lowercase()
                        .chars()
                        .filter(|c| !matches!(c, '.' | ' ' | ':' | '-'))
                        .collect();
                    value = compact
                        .chunks(2)
                        .map(|chunk| chunk.iter().collect::<String>())
                        .collect::<Vec<_>>()
                        .join(":");
                }
                "normalize_phone" => {
                    if value.starts_with("00") {
                        value = format!("+{}", &value[2..]);
                    }
                    value = value
                        .replace("(0)", "")
                        .chars()
                        .filter(|c| *c == '+' || c.is_ascii_digit())
                        .collect();
                }
                "normalize_ip_port" => value = normalize_ip_port(&value),
                "normalize_datetime" => {
                    if let Some(normalized) = normalize_datetime(&value) {
                        value = normalized
                    }
                }
                "normalize_vulnerability" => {
                    value = value.replace('–', "-");
                    if matches!(
                        value
                            .split('-')
                            .next()
                            .unwrap_or("")
                            .to_lowercase()
                            .as_str(),
                        "cve" | "gcve"
                    ) {
                        value = value.to_uppercase();
                    }
                }
                "normalize_ip" => value = normalize_ip(&value),
                "strip_prefix" => {
                    let prefix = required_text(operation, "value")?;
                    let matches = operation
                        .get("case_insensitive")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                        && value
                            .get(..prefix.len())
                            .is_some_and(|v| v.eq_ignore_ascii_case(prefix))
                        || value.starts_with(prefix);
                    if matches {
                        value = value[prefix.len()..].to_owned();
                    }
                }
                "asdot_to_asplain" => {
                    if let Some((high, low)) = value.split_once('.') {
                        if high.chars().all(|c| c.is_ascii_digit())
                            && low.chars().all(|c| c.is_ascii_digit())
                        {
                            if let (Ok(high), Ok(low)) = (high.parse::<u128>(), low.parse::<u128>())
                            {
                                if let Some(number) = high
                                    .checked_mul(65536)
                                    .and_then(|high| high.checked_add(low))
                                {
                                    value = number.to_string();
                                }
                            }
                        }
                    }
                }
                _ => return Err(RuleEngineError::UnsupportedNormalizer(op.to_owned())),
            }
        }
        Ok(value)
    }

    fn validate_rule(
        &self,
        rule: &Value,
        value: String,
    ) -> Result<(bool, String), RuleEngineError> {
        let op = required_text(rule, "op")?;
        let valid = match op {
            "any" => true,
            "numeric" => is_numeric(&value),
            "json" => serde_json::from_str::<Value>(&value).is_ok(),
            "url" => {
                !value.contains(['\r', '\n'])
                    && Url::parse(&value)
                        .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host().is_some())
            }
            "hash" => {
                let algorithm = required_text(rule, "algorithm")?;
                let definition = self
                    .spec
                    .get("definitions")
                    .and_then(|v| v.get("hashes"))
                    .and_then(|v| v.get(algorithm))
                    .ok_or_else(|| RuleEngineError::UnknownHashDefinition(algorithm.to_owned()))?;
                if text(definition.get("encoding")) != Some("hex") {
                    return Err(RuleEngineError::UnsupportedHashEncoding);
                }
                let lengths: Vec<u64> = definition["length"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_u64).collect())
                    .unwrap_or_else(|| definition["length"].as_u64().into_iter().collect());
                is_hex(&value) && lengths.contains(&(value.len() as u64))
            }
            "hex" => is_hex(&value),
            "regex" => RegexBuilder::new(required_text(rule, "pattern")?)
                .case_insensitive(
                    rule.get("case_insensitive")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                )
                .build()?
                .is_match(&value),
            "integer" => integer_is_valid(rule, &value),
            "boolean" => matches!(value.as_str(), "0" | "1"),
            "ip" => valid_ip(
                &value,
                rule.get("allow_cidr")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
            "string" => {
                let length = value.chars().count() as u64;
                length >= rule.get("min_length").and_then(Value::as_u64).unwrap_or(0)
                    && rule
                        .get("max_length")
                        .and_then(Value::as_u64)
                        .is_none_or(|max| length <= max)
                    && array(rule.get("forbidden"))
                        .iter()
                        .filter_map(Value::as_str)
                        .all(|token| !value.contains(token))
            }
            "datetime" => parse_datetime(&value).is_some(),
            "ssh_fingerprint" => valid_ssh_fingerprint(&value),
            "composite" => {
                let separator = required_text(rule, "separator")?;
                let parts: Vec<_> = value.split(separator).collect();
                let fields = array(rule.get("fields"));
                if parts.len() != fields.len() {
                    return Ok((false, value));
                }
                let mut normalized = Vec::new();
                for (part, field) in parts.iter().zip(fields) {
                    let part =
                        self.apply_normalizers((*part).to_owned(), array(field.get("normalize")))?;
                    let (valid, part) = self.validate_rule(required(field, "validate")?, part)?;
                    if !valid {
                        return Ok((false, value));
                    }
                    normalized.push(part);
                }
                return Ok((true, normalized.join(separator)));
            }
            _ => return Err(RuleEngineError::UnsupportedValidator(op.to_owned())),
        };
        Ok((valid, value))
    }
}

fn array(value: Option<&Value>) -> &[Value] {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn text(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn required<'a>(value: &'a Value, key: &str) -> Result<&'a Value, RuleEngineError> {
    value
        .get(key)
        .ok_or_else(|| RuleEngineError::MissingField(key.to_owned()))
}

fn required_text<'a>(value: &'a Value, key: &str) -> Result<&'a str, RuleEngineError> {
    required(value, key)?
        .as_str()
        .ok_or_else(|| RuleEngineError::InvalidFieldType(key.to_owned()))
}

fn is_numeric(value: &str) -> bool {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX
        .get_or_init(|| Regex::new(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$").unwrap())
        .is_match(value)
}

fn is_hex(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|c| c.is_ascii_hexdigit())
}

fn integer_is_valid(rule: &Value, value: &str) -> bool {
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if rule.get("min").is_none() && rule.get("max").is_none() {
        return true;
    }
    value.parse::<i128>().is_ok_and(|number| {
        rule.get("min")
            .and_then(Value::as_i64)
            .is_none_or(|min| number >= min as i128)
            && rule
                .get("max")
                .and_then(Value::as_i64)
                .is_none_or(|max| number <= max as i128)
    })
}

fn normalize_ip(value: &str) -> String {
    let (ip, prefix) = value
        .split_once('/')
        .map_or((value, None), |(ip, prefix)| (ip, Some(prefix)));
    let Ok(parsed) = IpAddr::from_str(ip) else {
        return value.to_owned();
    };
    let normalized = parsed.to_string();
    match (parsed, prefix) {
        (_, None) => normalized,
        (IpAddr::V4(_), Some("32")) | (IpAddr::V6(_), Some("128")) => normalized,
        (_, Some(prefix)) => format!("{normalized}/{prefix}"),
    }
}

fn valid_ip(value: &str, allow_cidr: bool) -> bool {
    let Some((ip, prefix)) = value.split_once('/') else {
        return IpAddr::from_str(value).is_ok();
    };
    allow_cidr
        && !prefix.contains('/')
        && IpAddr::from_str(ip).is_ok_and(|ip| {
            prefix
                .parse::<u8>()
                .is_ok_and(|p| p <= if ip.is_ipv4() { 32 } else { 128 })
        })
}
fn normalize_ip_port(value: &str) -> String {
    if let Some(rest) = value.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            return format!("{}|{port}", normalize_ip(host));
        }
    }
    for separator in ["|", " port ", "p", "#"] {
        if let Some((host, port)) = value.rsplit_once(separator) {
            return format!("{}|{port}", normalize_ip(host));
        }
    }
    value.rsplit_once(':').map_or_else(
        || value.to_owned(),
        |(host, port)| format!("{}|{port}", normalize_ip(host)),
    )
}

fn date_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$",
        )
        .unwrap()
    })
}

fn parse_datetime(value: &str) -> Option<(chrono::DateTime<FixedOffset>, String)> {
    let captures = date_regex().captures(value)?;
    let number = |index: usize| captures[index].parse::<u32>().ok();
    let (year, month, day, hour, minute, second) = (
        captures[1].parse::<i32>().ok()?,
        number(2)?,
        number(3)?,
        number(4)?,
        number(5)?,
        number(6)?,
    );
    let zone = captures.get(7).map(|m| m.as_str()).unwrap_or("Z");
    let offset_seconds = if zone == "Z" {
        0
    } else {
        let sign = if &zone[..1] == "+" { 1 } else { -1 };
        let compact = zone[1..].replace(':', "");
        sign * (compact[..2].parse::<i32>().ok()? * 3600 + compact[2..].parse::<i32>().ok()? * 60)
    };
    let offset = FixedOffset::east_opt(offset_seconds)?;
    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    let datetime = offset
        .from_local_datetime(&date.and_hms_opt(hour, minute, second)?)
        .single()?;
    Some((
        datetime,
        if zone == "Z" {
            "+0000".into()
        } else {
            zone.replace(':', "")
        },
    ))
}

fn normalize_datetime(value: &str) -> Option<String> {
    if let Some((datetime, offset)) = parse_datetime(value) {
        return Some(format!(
            "{}.{:06}{offset}",
            datetime.format("%Y-%m-%dT%H:%M:%S"),
            0
        ));
    }
    let captures = date_regex().captures(value)?;
    let day = captures[3].parse::<i64>().ok()?;
    let rebuilt = format!(
        "{}-{}-01T{}:{}:{}{}",
        &captures[1],
        &captures[2],
        &captures[4],
        &captures[5],
        &captures[6],
        captures.get(7).map(|m| m.as_str()).unwrap_or("Z")
    );
    let (datetime, offset) = parse_datetime(&rebuilt)?;
    let datetime = datetime + Duration::days(day - 1);
    Some(format!(
        "{}.{:06}{offset}",
        datetime.format("%Y-%m-%dT%H:%M:%S"),
        0
    ))
}

fn valid_ssh_fingerprint(value: &str) -> bool {
    if let Some(encoded) = value.strip_prefix("SHA256:") {
        let padded = format!("{encoded}{}", "=".repeat((4 - encoded.len() % 4) % 4));
        return STANDARD.decode(padded).is_ok_and(|bytes| bytes.len() == 32);
    }
    let digest = value.strip_prefix("MD5:").unwrap_or(value).replace(':', "");
    digest.len() == 32 && is_hex(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn engine(spec: Value) -> RuleEngine {
        RuleEngine::new(spec).unwrap()
    }

    // --- construction & type lookup ---

    #[test]
    fn new_rejects_spec_without_types_object() {
        assert!(matches!(
            RuleEngine::new(json!({})),
            Err(RuleEngineError::MissingTypes)
        ));
        assert!(matches!(
            RuleEngine::new(json!({"types": "not-an-object"})),
            Err(RuleEngineError::MissingTypes)
        ));
    }

    #[test]
    fn new_accepts_empty_types_object() {
        assert!(RuleEngine::new(json!({"types": {}})).is_ok());
    }

    #[test]
    fn unknown_type_is_reported() {
        let engine = engine(json!({"types": {}}));
        assert!(matches!(
            engine.normalize("md5", "x"),
            Err(RuleEngineError::UnknownType(name)) if name == "md5"
        ));
        assert!(matches!(
            engine.validate("md5", "x"),
            Err(RuleEngineError::UnknownType(name)) if name == "md5"
        ));
    }

    #[test]
    fn from_file_reports_io_error_for_missing_file() {
        assert!(matches!(
            RuleEngine::from_file("/nonexistent/does-not-exist.json"),
            Err(RuleEngineError::Io(_))
        ));
    }

    #[test]
    fn from_file_reports_json_error_for_invalid_json() {
        let path = std::env::temp_dir().join("misp-validation-test-invalid-spec.json");
        fs::write(&path, "not json").unwrap();
        let result = RuleEngine::from_file(&path);
        fs::remove_file(&path).unwrap();
        assert!(matches!(result, Err(RuleEngineError::Json(_))));
    }

    #[test]
    fn from_default_spec_validates_a_known_type() {
        let engine = RuleEngine::from_default_spec().unwrap();
        let result = engine
            .validate("md5", "d41d8cd98f00b204e9800998ecf8427e")
            .unwrap();
        assert!(result.valid);
    }

    // --- normalize/validate plumbing ---

    #[test]
    fn default_normalizers_apply_before_type_normalizers() {
        let engine = engine(json!({
            "defaults": {"normalize": [{"op": "trim"}]},
            "types": {
                "greeting": {
                    "normalize": [{"op": "uppercase"}],
                    "validate": {"op": "any"}
                }
            }
        }));
        assert_eq!(engine.normalize("greeting", "  hello  ").unwrap(), "HELLO");
    }

    #[test]
    fn validate_reports_configured_error_or_default() {
        let engine = engine(json!({
            "types": {
                "custom": {
                    "validate": {"op": "hex"},
                    "error": {"code": "bad_custom", "message": "Nope."}
                },
                "custom_default_error": {
                    "validate": {"op": "hex"}
                }
            }
        }));

        let result = engine.validate("custom", "zz").unwrap();
        assert!(!result.valid);
        assert_eq!(
            result.error,
            Some(ValidationError {
                code: "bad_custom".into(),
                message: "Nope.".into(),
            })
        );

        let result = engine.validate("custom_default_error", "zz").unwrap();
        assert_eq!(
            result.error,
            Some(ValidationError {
                code: "invalid_value".into(),
                message: "Invalid value.".into(),
            })
        );

        assert_eq!(engine.validate("custom", "ab").unwrap().error, None);
    }

    #[test]
    fn valid_types_lists_matching_types_only() {
        let engine = engine(json!({
            "types": {
                "hex_only": {"validate": {"op": "hex"}},
                "any_value": {"validate": {"op": "any"}},
                "numbers_only": {"validate": {"op": "numeric"}}
            }
        }));
        let mut types = engine.valid_types("ff").unwrap();
        types.sort();
        assert_eq!(types, vec!["any_value", "hex_only"]);
    }

    // --- apply_normalizers error paths ---

    #[test]
    fn normalizer_missing_op_field_is_reported() {
        let engine = engine(json!({
            "types": {"t": {"normalize": [{}], "validate": {"op": "any"}}}
        }));
        assert!(matches!(
            engine.normalize("t", "x"),
            Err(RuleEngineError::MissingField(field)) if field == "op"
        ));
    }

    #[test]
    fn normalizer_op_field_must_be_text() {
        let engine = engine(json!({
            "types": {"t": {"normalize": [{"op": 5}], "validate": {"op": "any"}}}
        }));
        assert!(matches!(
            engine.normalize("t", "x"),
            Err(RuleEngineError::InvalidFieldType(field)) if field == "op"
        ));
    }

    #[test]
    fn unsupported_normalizer_op_is_reported() {
        let engine = engine(json!({
            "types": {"t": {"normalize": [{"op": "nope"}], "validate": {"op": "any"}}}
        }));
        assert!(matches!(
            engine.normalize("t", "x"),
            Err(RuleEngineError::UnsupportedNormalizer(op)) if op == "nope"
        ));
    }

    // --- validate_rule error paths & validators ---

    #[test]
    fn missing_validate_rule_is_reported() {
        let engine = engine(json!({"types": {"t": {}}}));
        assert!(matches!(
            engine.validate("t", "x"),
            Err(RuleEngineError::MissingField(field)) if field == "validate"
        ));
    }

    #[test]
    fn unsupported_validator_op_is_reported() {
        let engine = engine(json!({
            "types": {"t": {"validate": {"op": "nope"}}}
        }));
        assert!(matches!(
            engine.validate("t", "x"),
            Err(RuleEngineError::UnsupportedValidator(op)) if op == "nope"
        ));
    }

    #[test]
    fn unknown_hash_definition_is_reported() {
        let engine = engine(json!({
            "types": {"t": {"validate": {"op": "hash", "algorithm": "sha1"}}}
        }));
        assert!(matches!(
            engine.validate("t", "x"),
            Err(RuleEngineError::UnknownHashDefinition(algorithm)) if algorithm == "sha1"
        ));
    }

    #[test]
    fn non_hex_hash_encoding_is_rejected() {
        let engine = engine(json!({
            "definitions": {"hashes": {"custom": {"encoding": "base64", "length": 10}}},
            "types": {"t": {"validate": {"op": "hash", "algorithm": "custom"}}}
        }));
        assert!(matches!(
            engine.validate("t", "x"),
            Err(RuleEngineError::UnsupportedHashEncoding)
        ));
    }

    #[test]
    fn hash_accepts_any_configured_length() {
        let engine = engine(json!({
            "definitions": {"hashes": {"custom": {"encoding": "hex", "length": [4, 8]}}},
            "types": {"t": {"validate": {"op": "hash", "algorithm": "custom"}}}
        }));
        assert!(engine.validate("t", "abcd").unwrap().valid);
        assert!(engine.validate("t", "abcdef12").unwrap().valid);
        assert!(!engine.validate("t", "abc").unwrap().valid);
    }

    #[test]
    fn invalid_regex_pattern_is_reported() {
        let engine = engine(json!({
            "types": {"t": {"validate": {"op": "regex", "pattern": "("}}}
        }));
        assert!(matches!(
            engine.validate("t", "x"),
            Err(RuleEngineError::Regex(_))
        ));
    }

    #[test]
    fn string_validator_enforces_length_and_forbidden_tokens() {
        let engine = engine(json!({
            "types": {
                "t": {
                    "validate": {
                        "op": "string",
                        "min_length": 2,
                        "max_length": 4,
                        "forbidden": ["bad"]
                    }
                }
            }
        }));
        assert!(engine.validate("t", "ok").unwrap().valid);
        assert!(!engine.validate("t", "a").unwrap().valid);
        assert!(!engine.validate("t", "toolong").unwrap().valid);
        assert!(!engine.validate("t", "badx").unwrap().valid);
    }

    // --- composite validator ---

    #[test]
    fn composite_validates_and_normalizes_each_field() {
        let engine = engine(json!({
            "types": {
                "pair": {
                    "validate": {
                        "op": "composite",
                        "separator": "|",
                        "fields": [
                            {"normalize": [{"op": "lowercase"}], "validate": {"op": "hex"}},
                            {"validate": {"op": "numeric"}}
                        ]
                    }
                }
            }
        }));
        let result = engine.validate("pair", "AB|42").unwrap();
        assert!(result.valid);
        assert_eq!(result.value, "ab|42");
    }

    #[test]
    fn composite_rejects_wrong_field_count() {
        let engine = engine(json!({
            "types": {
                "pair": {
                    "validate": {
                        "op": "composite",
                        "separator": "|",
                        "fields": [{"validate": {"op": "any"}}, {"validate": {"op": "any"}}]
                    }
                }
            }
        }));
        assert!(!engine.validate("pair", "only-one").unwrap().valid);
    }

    // --- normalizer nuances ---

    #[test]
    fn strip_prefix_respects_case_insensitive_flag() {
        let case_sensitive = engine(json!({
            "types": {"t": {
                "normalize": [{"op": "strip_prefix", "value": "MD5:"}],
                "validate": {"op": "any"}
            }}
        }));
        assert_eq!(case_sensitive.normalize("t", "md5:abc").unwrap(), "md5:abc");
        assert_eq!(case_sensitive.normalize("t", "MD5:abc").unwrap(), "abc");

        let case_insensitive = engine(json!({
            "types": {"t": {
                "normalize": [{"op": "strip_prefix", "value": "MD5:", "case_insensitive": true}],
                "validate": {"op": "any"}
            }}
        }));
        assert_eq!(case_insensitive.normalize("t", "md5:abc").unwrap(), "abc");
    }

    #[test]
    fn trim_chars_uses_configured_character_set() {
        let engine = engine(json!({
            "types": {"t": {
                "normalize": [{"op": "trim_chars", "characters": "#*"}],
                "validate": {"op": "any"}
            }}
        }));
        assert_eq!(engine.normalize("t", "##hello**").unwrap(), "hello");
    }

    #[test]
    fn replace_non_bmp_uses_configured_replacement() {
        let engine = engine(json!({
            "types": {"t": {
                "normalize": [{"op": "replace_non_bmp", "replacement": "!"}],
                "validate": {"op": "any"}
            }}
        }));
        assert_eq!(engine.normalize("t", "a\u{1F600}b").unwrap(), "a!b");
    }

    // --- Display impls ---

    #[test]
    fn validation_error_display_includes_code_and_message() {
        let error = ValidationError {
            code: "bad".into(),
            message: "Broken.".into(),
        };
        assert_eq!(error.to_string(), "Broken. (bad)");
    }

    #[test]
    fn rule_engine_error_messages() {
        assert_eq!(
            RuleEngineError::UnknownType("md5".into()).to_string(),
            "unknown attribute type: md5"
        );
        assert_eq!(
            RuleEngineError::MissingTypes.to_string(),
            "specification has no types object"
        );
    }

    // --- private helper functions ---

    #[test]
    fn is_numeric_accepts_common_numeric_forms() {
        for valid in [
            "0",
            "42",
            "-3.14",
            "+123456789",
            "6.02e23",
            ".5",
            "5.",
            "5e10",
            "5E-10",
            "-0",
        ] {
            assert!(is_numeric(valid), "expected {valid:?} to be numeric");
        }
    }

    #[test]
    fn is_numeric_rejects_malformed_input() {
        for invalid in [
            "",
            "+",
            "-",
            ".",
            "1.2.3",
            "5e",
            "5e+",
            "5e-",
            "not-a-number",
            "5 ",
            " 5",
            "5\n",
        ] {
            assert!(!is_numeric(invalid), "expected {invalid:?} to be rejected");
        }
    }

    #[test]
    fn is_numeric_matches_retired_regex_grammar() {
        // `is_numeric` replaced a regex match on this exact pattern for
        // performance; this pins the two implementations together so a
        // future edit to either can't silently diverge.
        let reference = Regex::new(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$").unwrap();
        let cases = [
            "",
            "+",
            "-",
            ".",
            "0",
            "-0",
            "+0",
            "5.",
            ".5",
            "5.5",
            "5..5",
            "..5",
            "5.5.5",
            "5e",
            "5e+",
            "5e-",
            "5e5",
            "5e+5",
            "5e-5",
            "5E5",
            "+5e-5",
            "-.5",
            "5.e5",
            "0123",
            "-0123",
            "5 ",
            " 5",
            "5\n",
            "5\t",
            "42",
            "-3.14",
            "6.02e23",
            "not-a-number",
            "1.2.3",
            "inf",
            "nan",
            "NaN",
            "Infinity",
        ];
        for case in cases {
            assert_eq!(
                is_numeric(case),
                reference.is_match(case),
                "mismatch for {case:?}"
            );
        }
    }

    #[test]
    fn is_numeric_accepts_unicode_digits() {
        // `\d` in the `regex` crate matches any Unicode decimal digit, not
        // just ASCII 0-9, so this also accepts non-ASCII digit scripts.
        assert!(is_numeric("٤٢")); // Arabic-Indic digits for "42"
        assert!(is_numeric("42"));
    }

    #[test]
    fn is_hex_rejects_empty_and_non_hex() {
        assert!(!is_hex(""));
        assert!(!is_hex("zz"));
        assert!(is_hex("deadBEEF"));
    }

    #[test]
    fn integer_is_valid_enforces_bounds() {
        let rule = json!({"min": 1, "max": 10});
        assert!(integer_is_valid(&rule, "5"));
        assert!(!integer_is_valid(&rule, "0"));
        assert!(!integer_is_valid(&rule, "11"));
        assert!(!integer_is_valid(&rule, "abc"));
        assert!(integer_is_valid(&json!({}), "-123"));
    }

    #[test]
    fn normalize_ip_strips_default_prefix_lengths() {
        assert_eq!(normalize_ip("192.168.0.1/32"), "192.168.0.1");
        assert_eq!(normalize_ip("192.168.0.1/24"), "192.168.0.1/24");
        assert_eq!(normalize_ip("::1/128"), "::1");
        assert_eq!(normalize_ip("not-an-ip"), "not-an-ip");
    }

    #[test]
    fn valid_ip_respects_allow_cidr() {
        assert!(valid_ip("192.168.0.1", false));
        assert!(!valid_ip("192.168.0.1/24", false));
        assert!(valid_ip("192.168.0.1/24", true));
        assert!(!valid_ip("192.168.0.1/33", true));
        assert!(!valid_ip("192.168.0.1/24/24", true));
    }

    #[test]
    fn normalize_ip_port_handles_bracketed_ipv6() {
        assert_eq!(normalize_ip_port("[::1]:8080"), "::1|8080");
    }

    #[test]
    fn normalize_ip_port_handles_plain_host_port() {
        assert_eq!(normalize_ip_port("192.168.0.1:8080"), "192.168.0.1|8080");
        assert_eq!(normalize_ip_port("hostvalue"), "hostvalue");
    }

    #[test]
    fn parse_datetime_rejects_invalid_calendar_dates() {
        assert!(parse_datetime("2024-02-30T00:00:00Z").is_none());
        assert!(parse_datetime("not-a-date").is_none());
        assert!(parse_datetime("2024-02-29T00:00:00Z").is_some());
    }

    #[test]
    fn normalize_datetime_rolls_overflowing_day_into_next_month() {
        assert_eq!(
            normalize_datetime("2024-02-30T00:00:00Z"),
            Some("2024-03-01T00:00:00.000000+0000".into())
        );
    }

    #[test]
    fn normalize_datetime_normalizes_offset_and_fraction() {
        assert_eq!(
            normalize_datetime("2024-01-02 03:04:05+02:00"),
            Some("2024-01-02T03:04:05.000000+0200".into())
        );
    }

    #[test]
    fn normalize_datetime_rejects_garbage() {
        assert_eq!(normalize_datetime("not-a-date"), None);
    }

    #[test]
    fn valid_ssh_fingerprint_accepts_md5_and_sha256_forms() {
        assert!(valid_ssh_fingerprint(
            "MD5:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
        ));
        assert!(!valid_ssh_fingerprint("MD5:aabb"));
        assert!(valid_ssh_fingerprint(
            "SHA256:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        ));
        assert!(!valid_ssh_fingerprint("SHA256:not-base64!!"));
    }
}
