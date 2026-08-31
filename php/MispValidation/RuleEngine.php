<?php

declare(strict_types=1);

namespace MispValidation;

use DateTimeImmutable;
use InvalidArgumentException;
use JsonException;
use RuntimeException;

final readonly class ValidationError
{
    public function __construct(public string $code, public string $message)
    {
    }
}

final readonly class ValidationResult
{
    public function __construct(
        public bool $valid,
        public string $value,
        public ?ValidationError $error = null,
    ) {
    }
}

/** Interprets the language-independent MISP attribute rule document. */
final class RuleEngine
{
    /** @var array<string, mixed> */
    private array $types;
    /** @var list<array<string, mixed>> */
    private array $defaultNormalizers;
    /** @var array<string, array<string, mixed>> */
    private array $hashes;

    /** @param array<string, mixed> $spec */
    public function __construct(private readonly array $spec)
    {
        $this->types = $spec['types'];
        $this->defaultNormalizers = $spec['defaults']['normalize'] ?? [];
        $this->hashes = $spec['definitions']['hashes'] ?? [];
    }

    /** @throws JsonException */
    public static function fromFile(string $path): self
    {
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new RuntimeException("Unable to read rule file: {$path}");
        }

        return new self(json_decode($contents, true, flags: JSON_THROW_ON_ERROR));
    }

    public function normalize(string $typeName, string $value): string
    {
        $rule = $this->typeRule($typeName);
        $value = $this->applyNormalizers($value, $this->defaultNormalizers);
        return $this->applyNormalizers($value, $rule['normalize'] ?? []);
    }

    public function validate(string $typeName, mixed $value): ValidationResult
    {
        $rule = $this->typeRule($typeName);
        $normalized = $this->applyNormalizers((string) $value, $this->defaultNormalizers);
        $normalized = $this->applyNormalizers($normalized, $rule['normalize'] ?? []);
        [$valid, $finalValue] = $this->validateRule($rule['validate'], $normalized);
        if ($valid) {
            return new ValidationResult(true, $finalValue);
        }

        $error = $rule['error'] ?? ['code' => 'invalid_value', 'message' => 'Invalid value.'];
        return new ValidationResult(false, $finalValue, new ValidationError($error['code'], $error['message']));
    }

    /** @return list<string> */
    public function validTypes(string $value): array
    {
        return array_values(array_filter(
            array_keys($this->types),
            fn (string $name): bool => $this->validate($name, $value)->valid,
        ));
    }

    /** @return array<string, mixed> */
    private function typeRule(string $typeName): array
    {
        if (!isset($this->types[$typeName])) {
            throw new InvalidArgumentException("Unknown attribute type: {$typeName}");
        }
        return $this->types[$typeName];
    }

    /** @param list<array<string, mixed>> $operations */
    private function applyNormalizers(string $value, array $operations): string
    {
        foreach ($operations as $operation) {
            $value = match ($operation['op']) {
                'lowercase' => mb_strtolower($value, 'UTF-8'),
                'uppercase' => mb_strtoupper($value, 'UTF-8'),
                'trim' => trim($value),
                'trim_chars' => trim($value, $operation['characters']),
                'replace' => str_replace($operation['old'], $operation['new'], $value),
                'replace_non_bmp' => preg_replace_callback(
                    '/[\x{10000}-\x{10FFFF}]/u',
                    static fn (): string => $operation['replacement'] ?? '?',
                    $value,
                ) ?? $value,
                'normalize_boolean' => match ($value) {
                    'true' => '1',
                    'false' => '0',
                    default => $value,
                },
                'regex_replace' => preg_replace('~' . str_replace('~', '\\~', $operation['pattern']) . '~u', $operation['replacement'] ?? '', $value) ?? $value,
                'normalize_mac' => implode(':', str_split(str_replace(['.', ':', '-', ' '], '', strtolower($value)), 2)),
                'normalize_phone' => $this->normalizePhone($value),
                'normalize_ip_port' => $this->normalizeIpPort($value),
                'normalize_datetime' => $this->normalizeDateTime($value),
                'normalize_vulnerability' => $this->normalizeVulnerability($value),
                'normalize_ip' => $this->normalizeIp($value),
                'strip_prefix' => $this->stripPrefix($value, $operation),
                'asdot_to_asplain' => $this->asdotToAsplain($value),
                default => throw new InvalidArgumentException("Unsupported normalizer op: {$operation['op']}"),
            };
        }
        return $value;
    }

    /** @param array<string, mixed> $rule @return array{bool, string} */
    private function validateRule(array $rule, string $value): array
    {
        switch ($rule['op']) {
            case 'any':
                return [true, $value];
            case 'numeric':
                return [is_numeric($value), $value];
            case 'json':
                json_decode($value);
                return [json_last_error() === JSON_ERROR_NONE, $value];
            case 'url':
                return [preg_match('/^https?:\\/\\//i', $value) === 1 && filter_var($value, FILTER_VALIDATE_URL) !== false, $value];
            case 'hash':
                $definition = $this->hashes[$rule['algorithm']];
                if ($definition['encoding'] !== 'hex') {
                    throw new InvalidArgumentException('Only hex hashes are supported by prototype');
                }
                $lengths = is_array($definition['length']) ? $definition['length'] : [$definition['length']];
                return [$this->isHex($value) && in_array(strlen($value), $lengths, true), $value];
            case 'hex':
                return [$this->isHex($value), $value];
            case 'regex':
                $delimiter = '~';
                $pattern = $delimiter . str_replace($delimiter, '\\' . $delimiter, $rule['pattern']) . $delimiter
                    . (!empty($rule['case_insensitive']) ? 'i' : '') . 'D';
                return [preg_match($pattern, $value) === 1, $value];
            case 'integer':
                if (preg_match('/^[+-]?[0-9]+$/D', $value) !== 1) {
                    return [false, $value];
                }
                if (isset($rule['min']) && bccomp($value, (string) $rule['min']) < 0) {
                    return [false, $value];
                }
                if (isset($rule['max']) && bccomp($value, (string) $rule['max']) > 0) {
                    return [false, $value];
                }
                return [true, $value];
            case 'boolean':
                return [in_array($value, ['0', '1'], true), $value];
            case 'ip':
                return [$this->isIp($value, !empty($rule['allow_cidr'])), $value];
            case 'string':
                if (mb_strlen($value, 'UTF-8') < ($rule['min_length'] ?? 0)) {
                    return [false, $value];
                }
                if (isset($rule['max_length']) && mb_strlen($value, 'UTF-8') > $rule['max_length']) {
                    return [false, $value];
                }
                foreach ($rule['forbidden'] ?? [] as $token) {
                    if (str_contains($value, $token)) {
                        return [false, $value];
                    }
                }
                return [true, $value];
            case 'datetime':
                return [$this->isDateTime($value), $value];
            case 'ssh_fingerprint':
                return [$this->isSshFingerprint($value), $value];
            case 'composite':
                $parts = explode($rule['separator'], $value);
                if (count($parts) !== count($rule['fields'])) {
                    return [false, $value];
                }
                $normalizedParts = [];
                foreach ($rule['fields'] as $index => $field) {
                    $part = $this->applyNormalizers($parts[$index], $field['normalize'] ?? []);
                    [$valid, $part] = $this->validateRule($field['validate'], $part);
                    if (!$valid) {
                        return [false, $value];
                    }
                    $normalizedParts[] = $part;
                }
                return [true, implode($rule['separator'], $normalizedParts)];
            default:
                throw new InvalidArgumentException("Unsupported validator op: {$rule['op']}");
        }
    }

    private static function isHex(string $value): bool
    {
        return $value !== '' && ctype_xdigit($value);
    }

    private static function normalizeIp(string $value): string
    {
        if (str_contains($value, '/')) {
            [$ip, $prefix] = explode('/', $value, 2);
            $packed = @inet_pton($ip);
            if ($packed === false) {
                return $value;
            }
            $ip = inet_ntop($packed);
            if (($prefix === '32' && strlen($packed) === 4) || ($prefix === '128' && strlen($packed) === 16)) {
                return $ip;
            }
            return "{$ip}/{$prefix}";
        }
        $packed = @inet_pton($value);
        return $packed === false ? $value : inet_ntop($packed);
    }

    private static function isIp(string $value, bool $allowCidr): bool
    {
        if (!str_contains($value, '/')) {
            return filter_var($value, FILTER_VALIDATE_IP) !== false;
        }
        if (!$allowCidr) {
            return false;
        }
        [$ip, $prefix] = explode('/', $value, 2);
        $packed = @inet_pton($ip);
        if ($packed === false || preg_match('/^[0-9]+$/D', $prefix) !== 1) {
            return false;
        }
        return (int) $prefix <= (strlen($packed) === 4 ? 32 : 128);
    }

    private static function isDateTime(string $value): bool
    {
        if (preg_match('/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/D', $value) !== 1) {
            return false;
        }
        try {
            $date = new DateTimeImmutable($value);
            return $date->format('Y-m-d') === substr($value, 0, 10);
        } catch (\Exception) {
            return false;
        }
    }

    private static function isSshFingerprint(string $value): bool
    {
        if (str_starts_with($value, 'SHA256:')) {
            $encoded = substr($value, 7);
            $encoded .= str_repeat('=', (4 - strlen($encoded) % 4) % 4);
            $decoded = base64_decode($encoded, true);
            return $decoded !== false && strlen($decoded) === 32;
        }
        $digest = str_starts_with($value, 'MD5:') ? substr($value, 4) : $value;
        $digest = str_replace(':', '', $digest);
        return strlen($digest) === 32 && self::isHex($digest);
    }

    /** @param array<string, mixed> $operation */
    private static function stripPrefix(string $value, array $operation): string
    {
        $prefix = $operation['value'];
        $matches = !empty($operation['case_insensitive'])
            ? strncasecmp($value, $prefix, strlen($prefix)) === 0
            : str_starts_with($value, $prefix);
        return $matches ? substr($value, strlen($prefix)) : $value;
    }

    private static function asdotToAsplain(string $value): string
    {
        if (preg_match('/^([0-9]+)\.([0-9]+)$/D', $value, $matches) !== 1) {
            return $value;
        }
        return bcadd(bcmul($matches[1], '65536'), $matches[2]);
    }

    private static function normalizeVulnerability(string $value): string
    {
        $value = str_replace('–', '-', $value);
        $source = explode('-', $value, 2)[0];
        return in_array(strtolower($source), ['cve', 'gcve'], true) ? strtoupper($value) : $value;
    }

    private static function normalizePhone(string $value): string
    {
        if (str_starts_with($value, '00')) {
            $value = '+' . substr($value, 2);
        }
        $value = preg_replace('/\\(0\\)/', '', $value) ?? $value;
        return preg_replace('/[^+0-9]+/', '', $value) ?? $value;
    }

    private static function normalizeIpPort(string $value): string
    {
        if (preg_match('/^\\[([^]]+)]:(.*)$/', $value, $matches) === 1) {
            return self::normalizeIp($matches[1]) . '|' . $matches[2];
        }
        foreach (['|', ' port ', 'p', '#'] as $separator) {
            $position = strrpos($value, $separator);
            if ($position !== false) {
                return self::normalizeIp(substr($value, 0, $position)) . '|' . substr($value, $position + strlen($separator));
            }
        }
        $position = strrpos($value, ':');
        return $position === false ? $value : self::normalizeIp(substr($value, 0, $position)) . '|' . substr($value, $position + 1);
    }

    private static function normalizeDateTime(string $value): string
    {
        try {
            return (new DateTimeImmutable($value, new \DateTimeZone('GMT')))->format('Y-m-d\\TH:i:s.uO');
        } catch (\Exception) {
            return $value;
        }
    }
}
