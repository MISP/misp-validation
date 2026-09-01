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
- `typescript/src/index.ts` — TypeScript interpreter with the same public operations.
- `rust/src/lib.rs` — Rust interpreter and crate with the same public operations.
- `tests/vectors.json` — language-independent conformance vectors.
- Runtime tests execute the same vectors in Python, PHP, TypeScript, and Rust.

## Run

```bash
python tests/test_runtime.py
php -d zend.assertions=1 -d assert.exception=1 tests/test_runtime.php
npm install
npm test
cargo test --manifest-path rust/Cargo.toml
```

All runtimes are checked against the same vectors. The pinned upstream MISP
source can also be executed as an oracle (rather than vendoring it):

```bash
curl -fsSLo /tmp/AttributeValidationTool.php \
  https://raw.githubusercontent.com/MISP/MISP/843b67445060e4da71ebf75cc4a9646c301f749d/app/Lib/Tools/AttributeValidationTool.php
php -d zend.assertions=1 -d assert.exception=1 \
  tests/test_upstream.php /tmp/AttributeValidationTool.php
```

The oracle runner also verifies that normalization and validation vectors have
no known differences and that every upstream type is present, including types
that MISP accepts without a type-specific validation rule.

## Install the Python package

The Python runtime requires Python 3.10 or newer and can be installed directly
from a checkout:

```bash
python -m pip install .
```

The package includes the default attribute specification, so no repository
paths are needed at runtime:

```python
from misp_validation import RuleEngine

engine = RuleEngine.from_default_spec()
result = engine.validate("md5", "d41d8cd98f00b204e9800998ecf8427e")
assert result.valid
```

To build the source distribution and wheel that can be uploaded to PyPI:

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

The upload command uses the PyPI credentials configured for Twine. Increment
the version in `pyproject.toml` before publishing a new release because PyPI
does not allow an existing release file to be replaced.

## Use the TypeScript package

```typescript
import { RuleEngine } from "misp-validation";

const engine = RuleEngine.fromDefaultSpec();
const result = engine.validate("md5", "d41d8cd98f00b204e9800998ecf8427e");
console.assert(result.valid);
```

The npm package includes compiled declarations and the default attribute specification.

## Use the Rust crate

```rust
use misp_validation::RuleEngine;

let engine = RuleEngine::from_default_spec()?;
let result = engine.validate("md5", "d41d8cd98f00b204e9800998ecf8427e")?;
assert!(result.valid);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The crate compiles the default attribute specification into the library and also
supports loading a rule document at runtime with `RuleEngine::from_file`.

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
- Add more runtimes early to keep verifying language independence.
