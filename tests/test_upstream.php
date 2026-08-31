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
$knownDifferences = [];

$differences = [];
foreach ($vectors as $vector) {
    $normalized = AttributeValidationTool::modifyBeforeValidation($vector['type'], $vector['input']);
    $valid = AttributeValidationTool::validate($vector['type'], $normalized) === true;
    if ((string) $normalized !== $vector['normalized'] || $valid !== $vector['valid']) {
        $differences[] = $vector['type'] . '|' . $vector['input'];
    }
}

sort($differences);
sort($knownDifferences);
assert($differences === $knownDifferences, 'Unexpected difference from the pinned MISP validator');

// Keep every explicit upstream switch case in the portable specification,
// including types whose upstream validation is an unconditional `true`.
$source = file_get_contents($argv[1]);
$validateStart = strpos($source, 'public static function validate(');
$validateEnd = strpos($source, 'public static function validTypesForValue', $validateStart);
$validateSource = substr($source, $validateStart, $validateEnd - $validateStart);
preg_match_all("/case '([^']+)'/", $validateSource, $matches);
$upstreamTypes = array_values(array_unique($matches[1]));
// This name occurs solely in a commented-out legacy block.
$upstreamTypes = array_values(array_diff($upstreamTypes, ['targeted-threat-index']));
$spec = json_decode(file_get_contents(__DIR__ . '/../spec/attributes.json'), true, flags: JSON_THROW_ON_ERROR);
$specTypes = array_keys($spec['types']);
sort($upstreamTypes);
sort($specTypes);
assert($specTypes === $upstreamTypes, 'Portable type list differs from the pinned MISP validator');

echo 'OK: pinned MISP source executed all ' . count($vectors)
    . ' vectors (' . count($differences) . " documented semantic differences)\n";
