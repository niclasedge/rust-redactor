//! `redactor mock <file>` — schema-inferred mock data generator.
//!
//! Minimal scope: CSV only. Reads header + first data row to infer column
//! types, then generates N (default 10) deterministic mock rows.

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, Copy)]
enum ColType {
    Int,
    Float,
    Bool,
    Email,
    Stringy,
}

fn infer_col_type(header: &str, sample: &str) -> ColType {
    let h = header.to_ascii_lowercase();
    if sample.parse::<i64>().is_ok() {
        return ColType::Int;
    }
    if sample.parse::<f64>().is_ok() {
        return ColType::Float;
    }
    if matches!(sample.to_ascii_lowercase().as_str(), "true" | "false") {
        return ColType::Bool;
    }
    if h.contains("email") || h.contains("mail") || sample.contains('@') {
        return ColType::Email;
    }
    ColType::Stringy
}

fn mock_value(t: ColType, idx: usize) -> String {
    match t {
        ColType::Int => format!("{idx}"),
        ColType::Float => format!("{idx}.0"),
        ColType::Bool => {
            if idx.is_multiple_of(2) {
                "true".into()
            } else {
                "false".into()
            }
        }
        ColType::Email => format!("user{idx}@example.com"),
        ColType::Stringy => format!("sample-{idx}"),
    }
}

/// Generate `rows` mock data rows that match the schema inferred from the
/// CSV header + first data row. Header is preserved verbatim; existing data
/// rows are dropped.
pub fn mock_csv(text: &str, rows: usize) -> Result<String> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut records = rdr.records();
    let header = match records.next() {
        Some(r) => r.context("read csv header")?,
        None => bail!("mock: empty csv"),
    };
    let first = records.next().transpose().context("read first data row")?;
    let types: Vec<ColType> = (0..header.len())
        .map(|i| {
            let h = header.get(i).unwrap_or("");
            let s = first.as_ref().and_then(|r| r.get(i)).unwrap_or("");
            infer_col_type(h, s)
        })
        .collect();

    let mut out = Vec::<u8>::new();
    {
        let mut w = csv::WriterBuilder::new().from_writer(&mut out);
        w.write_record(header.iter())?;
        for i in 1..=rows {
            let row: Vec<String> = types.iter().map(|t| mock_value(*t, i)).collect();
            w.write_record(row.iter())?;
        }
        w.flush()?;
    }
    String::from_utf8(out).context("csv output utf-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_infers_int_and_email_columns() {
        let input = "id,name,email\n42,Alice,alice@acme.com\n";
        let out = mock_csv(input, 3).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "id,name,email");
        assert_eq!(lines.len(), 4);
        assert!(lines[1].starts_with("1,"));
        assert!(lines[1].contains("@example.com"));
    }

    #[test]
    fn mock_header_only_fallback_to_string() {
        let input = "col_a,col_b,col_c\n";
        let out = mock_csv(input, 2).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        // No data row -> all columns inferred as Stringy
        assert!(lines[1].starts_with("sample-1,sample-1,sample-1"));
    }

    #[test]
    fn mock_zero_rows_only_header() {
        let input = "a,b\n1,2\n";
        let out = mock_csv(input, 0).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "a,b");
    }

    #[test]
    fn mock_bool_alternates() {
        let input = "active\ntrue\n";
        let out = mock_csv(input, 4).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[1], "false");
        assert_eq!(lines[2], "true");
        assert_eq!(lines[3], "false");
        assert_eq!(lines[4], "true");
    }

    #[test]
    fn mock_empty_errors() {
        let err = mock_csv("", 3).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }
}
