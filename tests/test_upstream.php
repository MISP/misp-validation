<?php

declare(strict_types=1);

if ($argc !== 2) {
    fwrite(STDERR, "Usage: php tests/test_upstream.php /path/to/AttributeValidationTool.php\n");
    exit(2);
}

// CakePHP normally provides this translation helper. The pinned validator only
// needs its formatting behavior when a conformance vector is invalid.
function __(string $message, mixed ...$arguments): string
{
    return $arguments === [] ? $message : vsprintf($message, $arguments);
}

require $argv[1];

$vectors = json_decode(file_get_contents(__DIR__ . '/vectors.json'), true, flags: JSON_THROW_ON_ERROR);
$knownDifferences = [
    // Upstream canonicalizes datetimes through DateTime; the portable rules
    // preserve valid input and deliberately reject rollover dates.
    'datetime|2024-02-29T12:34:56Z',
    'datetime|2023-02-29T12:34:56Z',
    // The pinned source lowercases x509 fingerprints; the current JSON rule
    // only describes validation for this type.
    'x509-fingerprint-sha256|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
];

$differences = [];
foreach ($vectors as $vector) {
    $normalized = AttributeValidationTool::modifyBeforeValidation($vector['type'], $vector['input']);
    $valid = AttributeValidationTool::validate($vector['type'], $normalized) === true;
    if ($normalized !== $vector['normalized'] || $valid !== $vector['valid']) {
        $differences[] = $vector['type'] . '|' . $vector['input'];
    }
}

sort($differences);
sort($knownDifferences);
assert($differences === $knownDifferences, 'Unexpected difference from the pinned MISP validator');

echo 'OK: pinned MISP source executed all ' . count($vectors)
    . ' vectors (' . count($differences) . " documented semantic differences)\n";
