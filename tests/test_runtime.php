<?php

declare(strict_types=1);

require dirname(__DIR__) . '/php/MispValidation/RuleEngine.php';

use MispValidation\RuleEngine;

$root = dirname(__DIR__);
$engine = RuleEngine::fromFile($root . '/spec/attributes.json');
$vectors = json_decode(file_get_contents($root . '/tests/vectors.json'), true, flags: JSON_THROW_ON_ERROR);

foreach ($vectors as $index => $vector) {
    $result = $engine->validate($vector['type'], $vector['input']);
    assert($result->valid === $vector['valid'], "vector {$index}: validity differs");
    assert($result->value === $vector['normalized'], "vector {$index}: normalized value differs");
}

echo 'OK: ' . count($vectors) . " validation vectors\n";
