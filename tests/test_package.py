import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from misp_validation import RuleEngine


engine = RuleEngine.from_default_spec()
result = engine.validate("md5", "d41d8cd98f00b204e9800998ecf8427e")
assert result.valid

source_spec = json.loads((ROOT / "spec" / "attributes.json").read_text(encoding="utf-8"))
assert engine.spec == source_spec, "The packaged and canonical specifications differ"

print("OK: packaged default specification")
