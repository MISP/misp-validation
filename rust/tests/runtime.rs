use misp_validation::RuleEngine;
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "type")]
    type_name: String,
    input: String,
    normalized: String,
    valid: bool,
}

#[test]
fn shared_conformance_vectors() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let engine = RuleEngine::from_file(root.join("spec/attributes.json")).unwrap();
    let default_engine = RuleEngine::from_default_spec().unwrap();
    let vectors: Vec<Vector> =
        serde_json::from_str(&fs::read_to_string(root.join("tests/vectors.json")).unwrap())
            .unwrap();

    for (index, vector) in vectors.iter().enumerate() {
        let result = engine.validate(&vector.type_name, &vector.input).unwrap();
        assert_eq!(
            result.valid, vector.valid,
            "vector {index}: validity differs"
        );
        assert_eq!(
            result.value, vector.normalized,
            "vector {index}: normalized value differs"
        );
        assert_eq!(
            default_engine
                .validate(&vector.type_name, &vector.input)
                .unwrap(),
            result,
            "vector {index}: bundled spec differs"
        );
    }

    println!("OK: {} validation vectors", vectors.len());
}
