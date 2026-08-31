from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from ipaddress import ip_address, ip_network
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class ValidationError:
    code: str
    message: str


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    value: str
    error: ValidationError | None = None


class RuleEngine:
    def __init__(self, spec: dict[str, Any]):
        self.spec = spec
        self.types = spec["types"]
        self.default_normalizers = spec.get("defaults", {}).get("normalize", [])
        self.hashes = spec.get("definitions", {}).get("hashes", {})

    @classmethod
    def from_file(cls, path: str | Path) -> "RuleEngine":
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    @classmethod
    def from_default_spec(cls) -> "RuleEngine":
        """Create an engine using the attribute rules bundled with the package."""
        spec = files("misp_validation").joinpath("_data/attributes.json")
        if not spec.is_file():
            # The package directory is mapped to ``python/misp_validation``
            # during development, while setuptools maps the canonical spec
            # directory into the installed package.
            spec = Path(__file__).resolve().parents[2] / "spec" / "attributes.json"
        with spec.open("r", encoding="utf-8") as f:
            return cls(json.load(f))

    def normalize(self, type_name: str, value: str) -> str:
        rule = self.types[type_name]
        value = self._apply_normalizers(value, self.default_normalizers)
        return self._apply_normalizers(value, rule.get("normalize", []))

    def validate(self, type_name: str, value: str) -> ValidationResult:
        if type_name not in self.types:
            raise KeyError(f"Unknown attribute type: {type_name}")

        rule = self.types[type_name]
        normalized = self._apply_normalizers(str(value), self.default_normalizers)
        normalized = self._apply_normalizers(normalized, rule.get("normalize", []))
        valid, final_value = self._validate_rule(rule["validate"], normalized)
        if valid:
            return ValidationResult(True, final_value)

        error = rule.get("error", {"code": "invalid_value", "message": "Invalid value."})
        return ValidationResult(False, final_value, ValidationError(error["code"], error["message"]))

    def valid_types(self, value: str) -> list[str]:
        return [name for name in self.types if self.validate(name, value).valid]

    def _apply_normalizers(self, value: str, operations: list[dict[str, Any]]) -> str:
        for operation in operations:
            op = operation["op"]
            if op == "lowercase":
                value = value.lower()
            elif op == "trim":
                value = value.strip()
            elif op == "trim_chars":
                value = value.strip(operation["characters"])
            elif op == "uppercase":
                value = value.upper()
            elif op == "replace":
                value = value.replace(operation["old"], operation["new"])
            elif op == "replace_non_bmp":
                replacement = operation.get("replacement", "?")
                value = "".join(ch if ord(ch) <= 0xFFFF else replacement for ch in value)
            elif op == "normalize_boolean":
                if value == "true":
                    value = "1"
                elif value == "false":
                    value = "0"
                else:
                    # Mirrors MISP boolean canonicalization: PHP truthiness is
                    # nuanced; the portable rule language will define the
                    # accepted textual input explicitly as this evolves.
                    value = value
            elif op == "regex_replace":
                value = re.sub(operation["pattern"], operation.get("replacement", ""), value)
            elif op == "normalize_mac":
                compact = re.sub(r"[. :\-]", "", value.lower())
                value = ":".join(compact[i : i + 2] for i in range(0, len(compact), 2))
            elif op == "normalize_phone":
                if value.startswith("00"):
                    value = "+" + value[2:]
                value = re.sub(r"\(0\)", "", value)
                value = re.sub(r"[^+0-9]+", "", value)
            elif op == "normalize_ip_port":
                value = self._normalize_ip_port(value)
            elif op == "normalize_datetime":
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    value = parsed.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
                except ValueError:
                    # PHP DateTime rolls overflowing calendar days into the
                    # following month (for example, February 29 in 2023).
                    match = re.fullmatch(
                        r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?",
                        value,
                    )
                    if match:
                        year, month, day, hour, minute, second = map(int, match.groups()[:6])
                        zone_text = match.group(7)
                        zone = timezone.utc
                        if zone_text and zone_text != "Z":
                            sign = 1 if zone_text[0] == "+" else -1
                            offset = zone_text[1:].replace(":", "")
                            zone = timezone(sign * timedelta(hours=int(offset[:2]), minutes=int(offset[2:])))
                        try:
                            parsed = datetime(year, month, 1, hour, minute, second, tzinfo=zone)
                            parsed += timedelta(days=day - 1)
                            value = parsed.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
                        except ValueError:
                            pass
            elif op == "normalize_vulnerability":
                value = value.replace("–", "-")
                if value.split("-", 1)[0].lower() in ("cve", "gcve"):
                    value = value.upper()
            elif op == "normalize_ip":
                value = self._normalize_ip(value)
            elif op == "strip_prefix":
                prefix = operation["value"]
                if operation.get("case_insensitive", False):
                    if value[: len(prefix)].lower() == prefix.lower():
                        value = value[len(prefix) :]
                elif value.startswith(prefix):
                    value = value[len(prefix) :]
            elif op == "asdot_to_asplain":
                if re.fullmatch(r"[0-9]+\.[0-9]+", value):
                    high, low = value.split(".", 1)
                    value = str(int(high) * 65536 + int(low))
            else:
                raise ValueError(f"Unsupported normalizer op: {op}")
        return value

    def _validate_rule(self, rule: dict[str, Any], value: str) -> tuple[bool, str]:
        op = rule["op"]

        if op == "any":
            return True, value

        if op == "numeric":
            return re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", value) is not None, value

        if op == "json":
            try:
                json.loads(value)
                return True, value
            except (ValueError, TypeError):
                return False, value

        if op == "url":
            parsed = urlparse(value)
            return parsed.scheme.lower() in ("http", "https") and bool(parsed.netloc), value

        if op == "hash":
            definition = self.hashes[rule["algorithm"]]
            if definition["encoding"] != "hex":
                raise ValueError("Only hex hashes are supported by prototype")
            lengths = definition["length"]
            if isinstance(lengths, int):
                lengths = [lengths]
            return self._is_hex(value) and len(value) in lengths, value

        if op == "hex":
            return self._is_hex(value), value

        if op == "regex":
            flags = re.IGNORECASE if rule.get("case_insensitive") else 0
            return re.fullmatch(rule["pattern"], value, flags) is not None, value

        if op == "integer":
            if not re.fullmatch(r"[+-]?[0-9]+", value):
                return False, value
            number = int(value)
            if "min" in rule and number < rule["min"]:
                return False, value
            if "max" in rule and number > rule["max"]:
                return False, value
            return True, value

        if op == "boolean":
            return value in ("0", "1"), value

        if op == "ip":
            try:
                if "/" in value:
                    if not rule.get("allow_cidr", False):
                        return False, value
                    ip_network(value, strict=False)
                else:
                    ip_address(value)
                return True, value
            except ValueError:
                return False, value

        if op == "string":
            if len(value) < rule.get("min_length", 0):
                return False, value
            if "max_length" in rule and len(value) > rule["max_length"]:
                return False, value
            for token in rule.get("forbidden", []):
                if token in value:
                    return False, value
            return True, value

        if op == "datetime":
            # Keep the accepted syntax deliberately narrower than Python's
            # parser: the portable specification promises ISO 8601 values.
            if re.fullmatch(
                r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
                value,
            ) is None:
                return False, value
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
                return True, value
            except ValueError:
                return False, value

        if op == "ssh_fingerprint":
            if value.startswith("SHA256:"):
                encoded = value[7:]
                try:
                    padding = "=" * (-len(encoded) % 4)
                    decoded = base64.b64decode(encoded + padding, validate=True)
                    return len(decoded) == 32, value
                except (ValueError, binascii.Error):
                    return False, value

            digest = value[4:] if value.startswith("MD5:") else value
            digest = digest.replace(":", "")
            return self._is_hex(digest) and len(digest) == 32, value

        if op == "composite":
            separator = rule["separator"]
            parts = value.split(separator)
            fields = rule["fields"]
            if len(parts) != len(fields):
                return False, value

            normalized_parts: list[str] = []
            for field, part in zip(fields, parts):
                normalized_part = self._apply_normalizers(part, field.get("normalize", []))
                valid, normalized_part = self._validate_rule(field["validate"], normalized_part)
                if not valid:
                    return False, value
                normalized_parts.append(normalized_part)
            return True, separator.join(normalized_parts)

        raise ValueError(f"Unsupported validator op: {op}")

    @staticmethod
    def _is_hex(value: str) -> bool:
        return bool(value) and re.fullmatch(r"[0-9a-fA-F]+", value) is not None

    @staticmethod
    def _normalize_ip(value: str) -> str:
        try:
            if "/" in value:
                ip_text, prefix = value.split("/", 1)
                ip = ip_address(ip_text)
                if (ip.version == 4 and prefix == "32") or (ip.version == 6 and prefix == "128"):
                    return ip.compressed
                return f"{ip.compressed}/{prefix}"
            return ip_address(value).compressed
        except ValueError:
            return value

    @classmethod
    def _normalize_ip_port(cls, value: str) -> str:
        if value.startswith("[") and "]" in value:
            end = value.index("]")
            return f"{cls._normalize_ip(value[1:end])}|{value[end + 1:].lstrip(':')}"
        for separator in ("|", " port ", "p", "#"):
            if separator in value:
                host, port = value.rsplit(separator, 1)
                return f"{cls._normalize_ip(host)}|{port}"
        if value.count(":") >= 2:
            host, port = value.rsplit(":", 1)
            return f"{cls._normalize_ip(host)}|{port}"
        if ":" in value:
            host, port = value.split(":", 1)
            return f"{cls._normalize_ip(host)}|{port}"
        return value
