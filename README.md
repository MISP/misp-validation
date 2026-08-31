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
- `tests/vectors.json` — language-independent conformance vectors.
- `tests/test_runtime.py` — Python conformance runner.

## Run

```bash
python tests/test_runtime.py
```

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
- Add a PHP oracle test harness against the pinned MISP implementation.
- Add a second runtime (Go or TypeScript) early to verify language independence.
