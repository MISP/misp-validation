import { isIP } from "node:net";
import { readFileSync } from "node:fs";

export interface ValidationError {
  code: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  value: string;
  error?: ValidationError;
}

type Rule = Record<string, any>;
export interface RuleSpec {
  defaults?: { normalize?: Rule[] };
  definitions?: { hashes?: Record<string, Rule> };
  types: Record<string, Rule>;
}

/** Interprets the language-independent MISP attribute rule document. */
export class RuleEngine {
  private readonly defaultNormalizers: Rule[];
  private readonly hashes: Record<string, Rule>;

  public constructor(private readonly spec: RuleSpec) {
    this.defaultNormalizers = spec.defaults?.normalize ?? [];
    this.hashes = spec.definitions?.hashes ?? {};
  }

  public static fromFile(path: string | URL): RuleEngine {
    return new RuleEngine(JSON.parse(readFileSync(path, "utf8")) as RuleSpec);
  }

  /** Create an engine using the attribute rules bundled with the package. */
  public static fromDefaultSpec(): RuleEngine {
    return RuleEngine.fromFile(new URL("../../spec/attributes.json", import.meta.url));
  }

  public normalize(typeName: string, value: string): string {
    const rule = this.typeRule(typeName);
    return this.applyNormalizers(this.applyNormalizers(value, this.defaultNormalizers), rule.normalize ?? []);
  }

  public validate(typeName: string, value: unknown): ValidationResult {
    const rule = this.typeRule(typeName);
    const normalized = this.applyNormalizers(
      this.applyNormalizers(String(value), this.defaultNormalizers),
      rule.normalize ?? [],
    );
    const [valid, finalValue] = this.validateRule(rule.validate, normalized);
    if (valid) return { valid: true, value: finalValue };
    return {
      valid: false,
      value: finalValue,
      error: rule.error ?? { code: "invalid_value", message: "Invalid value." },
    };
  }

  public validTypes(value: string): string[] {
    return Object.keys(this.spec.types).filter((name) => this.validate(name, value).valid);
  }

  private typeRule(typeName: string): Rule {
    const rule = this.spec.types[typeName];
    if (!rule) throw new Error(`Unknown attribute type: ${typeName}`);
    return rule;
  }

  private applyNormalizers(initial: string, operations: Rule[]): string {
    let value = initial;
    for (const operation of operations) {
      switch (operation.op) {
        case "lowercase": value = value.toLowerCase(); break;
        case "uppercase": value = value.toUpperCase(); break;
        case "trim": value = value.trim(); break;
        case "trim_chars": {
          const chars = [...operation.characters].map(escapeRegex).join("");
          value = value.replace(new RegExp(`^[${chars}]+|[${chars}]+$`, "gu"), "");
          break;
        }
        case "replace": value = value.split(operation.old).join(operation.new); break;
        case "replace_non_bmp":
          value = [...value].map((character) => character.codePointAt(0)! > 0xffff ? operation.replacement ?? "?" : character).join("");
          break;
        case "normalize_boolean":
          value = value === "true" ? "1" : value === "false" ? "0" : value;
          break;
        case "regex_replace": value = value.replace(new RegExp(operation.pattern, "gu"), operation.replacement ?? ""); break;
        case "normalize_mac": {
          const compact = value.toLowerCase().replace(/[. :\-]/g, "");
          value = compact.match(/.{1,2}/g)?.join(":") ?? "";
          break;
        }
        case "normalize_phone":
          if (value.startsWith("00")) value = `+${value.slice(2)}`;
          value = value.replace(/\(0\)/g, "").replace(/[^+0-9]+/g, "");
          break;
        case "normalize_ip_port": value = normalizeIpPort(value); break;
        case "normalize_datetime": value = normalizeDateTime(value); break;
        case "normalize_vulnerability": {
          value = value.replace(/–/g, "-");
          const source = value.split("-", 1)[0].toLowerCase();
          if (source === "cve" || source === "gcve") value = value.toUpperCase();
          break;
        }
        case "normalize_ip": value = normalizeIp(value); break;
        case "strip_prefix": {
          const prefix: string = operation.value;
          const matches = operation.case_insensitive
            ? value.slice(0, prefix.length).toLowerCase() === prefix.toLowerCase()
            : value.startsWith(prefix);
          if (matches) value = value.slice(prefix.length);
          break;
        }
        case "asdot_to_asplain": {
          const match = /^([0-9]+)\.([0-9]+)$/.exec(value);
          if (match) value = (BigInt(match[1]) * 65536n + BigInt(match[2])).toString();
          break;
        }
        default: throw new Error(`Unsupported normalizer op: ${operation.op}`);
      }
    }
    return value;
  }

  private validateRule(rule: Rule, value: string): [boolean, string] {
    switch (rule.op) {
      case "any": return [true, value];
      case "numeric": return [/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(value), value];
      case "json":
        try { JSON.parse(value); return [true, value]; } catch { return [false, value]; }
      case "url": {
        if (/[\r\n]/.test(value)) return [false, value];
        try { const url = new URL(value); return [["http:", "https:"].includes(url.protocol) && !!url.host, value]; }
        catch { return [false, value]; }
      }
      case "hash": {
        const definition = this.hashes[rule.algorithm];
        if (definition.encoding !== "hex") throw new Error("Only hex hashes are supported by prototype");
        const lengths = Array.isArray(definition.length) ? definition.length : [definition.length];
        return [isHex(value) && lengths.includes(value.length), value];
      }
      case "hex": return [isHex(value), value];
      case "regex": return [new RegExp(rule.pattern, rule.case_insensitive ? "iu" : "u").test(value), value];
      case "integer": {
        if (!/^[+-]?[0-9]+$/.test(value)) return [false, value];
        const number = BigInt(value);
        return [!(rule.min !== undefined && number < BigInt(rule.min)) && !(rule.max !== undefined && number > BigInt(rule.max)), value];
      }
      case "boolean": return [["0", "1"].includes(value), value];
      case "ip": return [isValidIp(value, rule.allow_cidr === true), value];
      case "string": {
        const length = [...value].length;
        if (length < (rule.min_length ?? 0) || (rule.max_length !== undefined && length > rule.max_length)) return [false, value];
        return [!(rule.forbidden ?? []).some((token: string) => value.includes(token)), value];
      }
      case "datetime": return [isDateTime(value), value];
      case "ssh_fingerprint": return [isSshFingerprint(value), value];
      case "composite": {
        const parts = value.split(rule.separator);
        if (parts.length !== rule.fields.length) return [false, value];
        const normalized: string[] = [];
        for (let index = 0; index < parts.length; index++) {
          const field = rule.fields[index];
          const part = this.applyNormalizers(parts[index], field.normalize ?? []);
          const [valid, finalPart] = this.validateRule(field.validate, part);
          if (!valid) return [false, value];
          normalized.push(finalPart);
        }
        return [true, normalized.join(rule.separator)];
      }
      default: throw new Error(`Unsupported validator op: ${rule.op}`);
    }
  }
}

function escapeRegex(value: string): string { return value.replace(/[\\\]^\-]/g, "\\$&"); }
function isHex(value: string): boolean { return value.length > 0 && /^[0-9a-f]+$/i.test(value); }

function parseIp(value: string): number[] | undefined {
  if (isIP(value) === 4) return value.split(".").map(Number);
  if (isIP(value) !== 6) return undefined;
  let text = value.toLowerCase();
  if (text.includes(".")) {
    const lastColon = text.lastIndexOf(":");
    const octets = text.slice(lastColon + 1).split(".").map(Number);
    text = `${text.slice(0, lastColon)}:${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const sides = text.split("::");
  const left = sides[0] ? sides[0].split(":") : [];
  const right = sides[1] ? sides[1].split(":") : [];
  return [...left, ...Array(8 - left.length - right.length).fill("0"), ...right].map((part) => parseInt(part, 16));
}

function normalizeIp(value: string): string {
  const slash = value.indexOf("/");
  const ipText = slash < 0 ? value : value.slice(0, slash);
  const prefix = slash < 0 ? undefined : value.slice(slash + 1);
  const parts = parseIp(ipText);
  if (!parts) return value;
  let result: string;
  if (parts.length === 4) result = parts.join(".");
  else {
    let bestStart = -1, bestLength = 0;
    for (let start = 0; start < 8;) {
      if (parts[start] !== 0) { start++; continue; }
      let end = start; while (end < 8 && parts[end] === 0) end++;
      if (end - start > bestLength && end - start >= 2) [bestStart, bestLength] = [start, end - start];
      start = end;
    }
    const before = parts.slice(0, bestStart < 0 ? 8 : bestStart).map((x) => x.toString(16)).join(":");
    const after = bestStart < 0 ? "" : parts.slice(bestStart + bestLength).map((x) => x.toString(16)).join(":");
    result = bestStart < 0 ? before : `${before}::${after}`;
  }
  if (prefix === undefined || (parts.length === 4 && prefix === "32") || (parts.length === 8 && prefix === "128")) return result;
  return `${result}/${prefix}`;
}

function isValidIp(value: string, allowCidr: boolean): boolean {
  if (!value.includes("/")) return isIP(value) !== 0;
  if (!allowCidr) return false;
  const [ip, prefix, extra] = value.split("/");
  const version = isIP(ip);
  return extra === undefined && version !== 0 && /^[0-9]+$/.test(prefix) && Number(prefix) <= (version === 4 ? 32 : 128);
}

function normalizeIpPort(value: string): string {
  const bracket = /^\[([^\]]+)]:(.*)$/.exec(value);
  if (bracket) return `${normalizeIp(bracket[1])}|${bracket[2]}`;
  for (const separator of ["|", " port ", "p", "#"]) {
    const position = value.lastIndexOf(separator);
    if (position >= 0) return `${normalizeIp(value.slice(0, position))}|${value.slice(position + separator.length)}`;
  }
  const position = value.lastIndexOf(":");
  return position < 0 ? value : `${normalizeIp(value.slice(0, position))}|${value.slice(position + 1)}`;
}

const datePattern = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/;
function normalizeDateTime(value: string): string {
  const match = datePattern.exec(value); if (!match) return value;
  const [, year, month, day, hour, minute, second, zoneText] = match;
  const offsetText = !zoneText || zoneText === "Z" ? "+0000" : zoneText.replace(":", "");
  const sign = offsetText[0] === "+" ? 1 : -1;
  const offset = sign * (Number(offsetText.slice(1, 3)) * 60 + Number(offsetText.slice(3, 5)));
  const timestamp = Date.UTC(+year, +month - 1, +day, +hour, +minute, +second) - offset * 60_000;
  if (!Number.isFinite(timestamp)) return value;
  const local = new Date(timestamp + offset * 60_000);
  const pad = (number: number) => String(number).padStart(2, "0");
  return `${local.getUTCFullYear()}-${pad(local.getUTCMonth() + 1)}-${pad(local.getUTCDate())}T${pad(local.getUTCHours())}:${pad(local.getUTCMinutes())}:${pad(local.getUTCSeconds())}.000000${offsetText}`;
}
function isDateTime(value: string): boolean {
  const match = datePattern.exec(value); if (!match) return false;
  const normalized = normalizeDateTime(value);
  return normalized.slice(0, 10) === value.slice(0, 10);
}
function isSshFingerprint(value: string): boolean {
  if (value.startsWith("SHA256:")) {
    try { return Buffer.from(value.slice(7), "base64").length === 32 && /^[A-Za-z0-9+/]+={0,2}$/.test(value.slice(7)); }
    catch { return false; }
  }
  const digest = (value.startsWith("MD5:") ? value.slice(4) : value).replace(/:/g, "");
  return digest.length === 32 && isHex(digest);
}
