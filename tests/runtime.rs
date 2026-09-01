use misp_validation::RuleEngine;
use serde::Deserialize;

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
    let vectors: Vec<Vector> = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let engine = RuleEngine::from_file("spec/attributes.json").unwrap();
    let default_engine = RuleEngine::from_default_spec().unwrap();
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
}
