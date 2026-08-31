# MISP Validation Prototype

A JSON-native, language-independent rule format for MISP attribute normalization and validation.

This prototype intentionally separates:

1. **Default normalization** — operations MISP applies to every value (currently non-BMP replacement).
2. **Type normalization** — canonicalization specific to an attribute type.
3. **Validation** — acceptance/rejection of the normalized value.
4. **Runtime** — language-specific implementation of generic operations.
5. **Conformance vectors** — shared tests that every runtime must pass.

## Files

- `spec/schema.json` — JSON Schema for the rule language.
- `spec/attributes.json` — initial rules derived from MISP `AttributeValidationTool.php`.
- `python/misp_validation/runtime.py` — Python interpreter for the rule language.
- `php/MispValidation/RuleEngine.php` — PHP interpreter with the same public operations.
- `tests/vectors.json` — language-independent conformance vectors.
- `tests/test_runtime.py` and `tests/test_runtime.php` — conformance runners for both runtimes.

## Run

```bash
python tests/test_runtime.py
php -d zend.assertions=1 -d assert.exception=1 tests/test_runtime.php
```

Both runtimes are checked against the same vectors. The pinned upstream MISP
source can also be executed as an oracle (rather than vendoring it):

```bash
curl -fsSLo /tmp/AttributeValidationTool.php \
  https://raw.githubusercontent.com/MISP/MISP/843b67445060e4da71ebf75cc4a9646c301f749d/app/Lib/Tools/AttributeValidationTool.php
php -d zend.assertions=1 -d assert.exception=1 \
  tests/test_upstream.php /tmp/AttributeValidationTool.php
```

The oracle runner documents the three intentional differences in the current
prototype: stricter/preserved datetimes and x509 fingerprint normalization.

## Design rule

The JSON must describe semantics, never Python/PHP/Go/Rust code. For example:

```json
{
  "normalize": [{"op": "lowercase"}],
  "validate": {"op": "hash", "algorithm": "md5"}
}
```

A backend/runtime decides how `lowercase` and `hash` are implemented.

## Next steps

- Formalize portable regex semantics.
- Add a second runtime (Go or TypeScript) early to verify language independence.
