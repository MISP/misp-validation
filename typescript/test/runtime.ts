import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { RuleEngine } from "../src/index.js";

const root = new URL("../../", import.meta.url);
const engine = RuleEngine.fromFile(new URL("spec/attributes.json", root));
const defaultEngine = RuleEngine.fromDefaultSpec();
const vectors = JSON.parse(readFileSync(new URL("tests/vectors.json", root), "utf8"));

vectors.forEach((vector: any, index: number) => {
  const result = engine.validate(vector.type, vector.input);
  assert.equal(result.valid, vector.valid, `vector ${index}: validity differs`);
  assert.equal(result.value, vector.normalized, `vector ${index}: normalized value differs`);
  assert.deepEqual(defaultEngine.validate(vector.type, vector.input), result, `vector ${index}: bundled spec differs`);
});

console.log(`OK: ${vectors.length} validation vectors`);
