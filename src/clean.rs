//! `redactor clean <file>` — anonymized variant of a structured file.
//!
//! Unlike `redactor <file>` (which keeps only the first row / first list
//! item and replaces leaves with `<redacted>`), `clean` preserves ALL rows /
//! ALL leaves and substitutes type-conformant placeholder values.
//!
//! Output goes to `<file>.clean` (e.g. `data.csv` -> `data.csv.clean`).

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// Anonymize a CSV: header verbatim, every cell in every data row replaced
/// with a type-heuristic placeholder (`0` for ints, `0.0` for floats,
/// `false` for bools, `sample` for strings).
pub fn clean_csv(text: &str) -> Result<String> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut records = rdr.records();
    let header = match records.next() {
        Some(r) => r.context("read csv header")?,
        None => bail!("clean: empty csv"),
    };
    let mut out = Vec::<u8>::new();
    {
        let mut w = csv::WriterBuilder::new().from_writer(&mut out);
        w.write_record(header.iter())?;
        for rec in records {
            let rec = rec.context("read csv record")?;
            let masked: Vec<String> = rec.iter().map(mock_cell).collect();
            w.write_record(masked.iter())?;
        }
        w.flush()?;
    }
    String::from_utf8(out).context("csv output utf-8")
}

fn mock_cell(s: &str) -> String {
    if s.parse::<i64>().is_ok() {
        "0".into()
    } else if s.parse::<f64>().is_ok() {
        "0.0".into()
    } else if matches!(s.to_ascii_lowercase().as_str(), "true" | "false") {
        "false".into()
    } else {
        "sample".into()
    }
}

/// Anonymize a JSON document: structure (nested objects, array length)
/// preserved, every leaf replaced with a type-conformant placeholder.
pub fn clean_json(text: &str) -> Result<String> {
    let v: Value = serde_json::from_str(text).context("parse json")?;
    let m = mock_value(&v);
    Ok(serde_json::to_string_pretty(&m)?)
}

fn mock_value(v: &Value) -> Value {
    match v {
        Value::Object(o) => {
            let mut out = serde_json::Map::new();
            for (k, val) in o {
                out.insert(k.clone(), mock_value(val));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(mock_value).collect()),
        Value::String(_) => Value::String("sample".into()),
        Value::Number(_) => Value::Number(0u64.into()),
        Value::Bool(_) => Value::Bool(false),
        Value::Null => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_csv_keeps_all_rows() {
        let input = "id,name\n1,Alice\n2,Bob\n3,Carol\n";
        let out = clean_csv(input).unwrap();
        assert!(out.starts_with("id,name"));
        assert_eq!(out.matches("sample").count(), 3);
    }

    #[test]
    fn clean_csv_type_heuristics() {
        let input = "n,x,active,name\n42,3.14,true,Alice\n";
        let out = clean_csv(input).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[1], "0,0.0,false,sample");
    }

    #[test]
    fn clean_csv_empty_errors() {
        let err = clean_csv("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn clean_json_preserves_structure() {
        let input = r#"{"k":"v","n":5,"a":[1,2,3]}"#;
        let out = clean_json(input).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["k"], "sample");
        assert_eq!(v["n"], 0);
        assert_eq!(v["a"][0], 0);
        assert_eq!(v["a"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn clean_json_recursive_objects() {
        let input = r#"{"outer":{"inner":"secret","arr":[true,false]}}"#;
        let out = clean_json(input).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["outer"]["inner"], "sample");
        assert_eq!(v["outer"]["arr"][0], false);
    }

    #[test]
    fn clean_json_invalid_errors() {
        let err = clean_json("{not json").unwrap_err();
        assert!(err.to_string().contains("parse"));
    }
}
