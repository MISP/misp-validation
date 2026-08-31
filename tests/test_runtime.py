import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from misp_validation import RuleEngine

engine = RuleEngine.from_file(ROOT / "spec" / "attributes.json")
vectors = json.loads((ROOT / "tests" / "vectors.json").read_text(encoding="utf-8"))

for vector in vectors:
    result = engine.validate(vector["type"], vector["input"])
    assert result.valid == vector["valid"], (vector, result)
    assert result.value == vector["normalized"], (vector, result)

print(f"OK: {len(vectors)} validation vectors")
