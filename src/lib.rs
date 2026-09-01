//! Rust interpreter for the language-independent MISP attribute rule document.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{Duration, FixedOffset, NaiveDate, TimeZone};
use regex::{Regex, RegexBuilder};
use serde_json::Value;
use std::{fmt, fs, net::IpAddr, path::Path, str::FromStr};
use url::Url;

/// A validation failure described by the attribute specification.
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Debug)]
pub struct RuleEngineError(String);

impl fmt::Display for RuleEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl std::error::Error for RuleEngineError {}
impl From<std::io::Error> for RuleEngineError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}
impl From<serde_json::Error> for RuleEngineError {
    fn from(error: serde_json::Error) -> Self {
        Self(error.to_string())
    }
}

/// Interprets normalization and validation operations from a JSON rule specification.
pub struct RuleEngine {
    spec: Value,
}

impl RuleEngine {
    pub fn new(spec: Value) -> Result<Self, RuleEngineError> {
        if spec.get("types").and_then(Value::as_object).is_none() {
            return Err(RuleEngineError("Specification has no types object".into()));
        }
        Ok(Self { spec })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RuleEngineError> {
        Self::new(serde_json::from_str(&fs::read_to_string(path)?)?)
    }

    /// Create an engine using the attribute rules compiled into this crate.
    pub fn from_default_spec() -> Result<Self, RuleEngineError> {
        Self::new(serde_json::from_str(include_str!(
            "../spec/attributes.json"
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
        for name in self.spec["types"].as_object().unwrap().keys() {
            if self.validate(name, value)?.valid {
                result.push(name.clone());
            }
        }
        Ok(result)
    }

    fn type_rule(&self, name: &str) -> Result<&Value, RuleEngineError> {
        self.spec["types"]
            .get(name)
            .ok_or_else(|| RuleEngineError(format!("Unknown attribute type: {name}")))
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
                    value = Regex::new(required_text(operation, "pattern")?)
                        .map_err(regex_error)?
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
                _ => return Err(RuleEngineError(format!("Unsupported normalizer op: {op}"))),
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
            "numeric" => Regex::new(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
                .unwrap()
                .is_match(&value),
            "json" => serde_json::from_str::<Value>(&value).is_ok(),
            "url" => {
                !value.contains(['\r', '\n'])
                    && Url::parse(&value)
                        .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host().is_some())
            }
            "hash" => {
                let definition = self
                    .spec
                    .get("definitions")
                    .and_then(|v| v.get("hashes"))
                    .and_then(|v| v.get(required_text(rule, "algorithm")?))
                    .ok_or_else(|| RuleEngineError("Unknown hash definition".into()))?;
                if text(definition.get("encoding")) != Some("hex") {
                    return Err(RuleEngineError(
                        "Only hex hashes are supported by prototype".into(),
                    ));
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
                .build()
                .map_err(regex_error)?
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
            _ => return Err(RuleEngineError(format!("Unsupported validator op: {op}"))),
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
        .ok_or_else(|| RuleEngineError(format!("Missing rule field: {key}")))
}
fn required_text<'a>(value: &'a Value, key: &str) -> Result<&'a str, RuleEngineError> {
    required(value, key)?
        .as_str()
        .ok_or_else(|| RuleEngineError(format!("Rule field is not text: {key}")))
}
fn regex_error(error: regex::Error) -> RuleEngineError {
    RuleEngineError(error.to_string())
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
    if prefix.is_none()
        || matches!(
            (parsed, prefix),
            (IpAddr::V4(_), Some("32")) | (IpAddr::V6(_), Some("128"))
        )
    {
        normalized
    } else {
        format!("{normalized}/{}", prefix.unwrap())
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

fn date_regex() -> Regex {
    Regex::new(
        r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$",
    )
    .unwrap()
}
fn parse_datetime(value: &str) -> Option<(chrono::DateTime<FixedOffset>, String)> {
    let captures = date_regex().captures(value)?;
    let number = |index| captures[index].parse::<u32>().ok();
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
