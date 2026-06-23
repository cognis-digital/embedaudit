// Rust port of the embedaudit core: audit a JSONL embedding snapshot for
// integrity + poisoning. Single static binary, standard library only (a tiny
// hand-rolled parser for the {"id","vector","text"} record shape — no crates).
// Mirrors the Python reference rule IDs and JSON output shape.
use std::collections::HashMap;
use std::{env, fs, process};

struct Record {
    id: String,
    vector: Vec<f64>,
}

struct Finding {
    severity: &'static str,
    code: &'static str,
    message: String,
}

fn norm(v: &[f64]) -> f64 {
    v.iter().map(|x| x * x).sum::<f64>().sqrt()
}

fn cosine(a: &[f64], b: &[f64], na: f64, nb: f64) -> f64 {
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    let d: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    d / (na * nb)
}

fn quant_key(v: &[f64]) -> String {
    v.iter()
        .map(|x| ((x * 1000.0).round() as i64).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

// Extract a string field value: "key":"value"
fn extract_str(line: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\"", key);
    let i = line.find(&pat)?;
    let rest = &line[i + pat.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    if !after.starts_with('"') {
        return None;
    }
    let body = &after[1..];
    let end = body.find('"')?;
    Some(body[..end].to_string())
}

// Extract the numeric "vector":[...] array.
fn extract_vector(line: &str) -> Option<Vec<f64>> {
    let i = line.find("\"vector\"")?;
    let rest = &line[i..];
    let lb = rest.find('[')?;
    let rb = rest.find(']')?;
    if rb <= lb {
        return None;
    }
    let inner = &rest[lb + 1..rb];
    if inner.trim().is_empty() {
        return Some(vec![]);
    }
    let mut out = Vec::new();
    for tok in inner.split(',') {
        out.push(tok.trim().parse::<f64>().ok()?);
    }
    Some(out)
}

fn load_jsonl(path: &str) -> Result<Vec<Record>, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut recs = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let vector = extract_vector(line)
            .ok_or_else(|| format!("line {}: missing/invalid 'vector'", i + 1))?;
        let id = extract_str(line, "id").unwrap_or_else(|| format!("line-{}", i + 1));
        recs.push(Record { id, vector });
    }
    if recs.is_empty() {
        return Err(format!("{}: no records loaded", path));
    }
    Ok(recs)
}

fn audit(mut recs: Vec<Record>, dup_threshold: f64, domination_share: f64) -> (bool, usize, usize, Vec<Finding>) {
    let mut findings: Vec<Finding> = Vec::new();

    // dimension consistency
    let mut dim_count: HashMap<usize, usize> = HashMap::new();
    for r in &recs {
        *dim_count.entry(r.vector.len()).or_insert(0) += 1;
    }
    let dim = *dim_count.iter().max_by_key(|(_, c)| **c).map(|(d, _)| d).unwrap_or(&0);
    if dim_count.len() != 1 {
        findings.push(Finding { severity: "critical", code: "DIM_MISMATCH", message: "Inconsistent vector dimensions".into() });
        recs.retain(|r| r.vector.len() == dim);
    }

    // norms, zero vectors, invalid values
    let mut norms = Vec::with_capacity(recs.len());
    let mut zero = 0usize;
    for r in &recs {
        if r.vector.iter().any(|x| x.is_nan() || x.is_infinite()) {
            findings.push(Finding { severity: "critical", code: "INVALID_VALUE", message: format!("Vector '{}' contains NaN/Inf", r.id) });
        }
        let n = norm(&r.vector);
        if n == 0.0 {
            zero += 1;
        }
        norms.push(n);
    }
    if zero > 0 {
        findings.push(Finding { severity: "critical", code: "ZERO_VECTOR", message: format!("{} zero-norm vector(s) (un-embeddable / corrupt)", zero) });
    }

    // duplicates
    let mut seen = std::collections::HashSet::new();
    let mut dups = 0usize;
    for r in &recs {
        if !seen.insert(quant_key(&r.vector)) {
            dups += 1;
        }
    }
    if dups > 0 {
        findings.push(Finding { severity: "warning", code: "DUPLICATE_VECTOR", message: format!("{} duplicate vector pair(s) detected", dups) });
    }

    // greedy clustering -> retrieval domination
    let mut heads: Vec<usize> = Vec::new();
    let mut clusters: Vec<usize> = Vec::new();
    for i in 0..recs.len() {
        let mut placed = false;
        for (hi, &h) in heads.iter().enumerate() {
            if cosine(&recs[i].vector, &recs[h].vector, norms[i], norms[h]) >= dup_threshold {
                clusters[hi] += 1;
                placed = true;
                break;
            }
        }
        if !placed {
            heads.push(i);
            clusters.push(1);
        }
    }
    let largest = *clusters.iter().max().unwrap_or(&0);
    let share = if recs.is_empty() { 0.0 } else { largest as f64 / recs.len() as f64 };
    if share >= domination_share && largest > 1 {
        findings.push(Finding { severity: "critical", code: "RETRIEVAL_DOMINATION", message: format!("{} near-identical vectors form {:.0}% of the store", largest, share * 100.0) });
    }

    let ok = !findings.iter().any(|f| f.severity == "critical");
    (ok, recs.len(), dim, findings)
}

fn print_json(ok: bool, count: usize, dim: usize, findings: &[Finding]) {
    println!("{{");
    println!("  \"ok\": {},", ok);
    println!("  \"record_count\": {},", count);
    println!("  \"dimension\": {},", dim);
    println!("  \"findings\": [");
    for (i, f) in findings.iter().enumerate() {
        let comma = if i + 1 < findings.len() { "," } else { "" };
        let msg = f.message.replace('\\', "\\\\").replace('"', "\\\"");
        println!("    {{\"severity\": \"{}\", \"code\": \"{}\", \"message\": \"{}\"}}{}", f.severity, f.code, msg, comma);
    }
    println!("  ]");
    println!("}}");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args[1] != "audit" {
        eprintln!("usage: embedaudit audit <snapshot.jsonl>");
        process::exit(2);
    }
    match load_jsonl(&args[2]) {
        Ok(recs) => {
            let (ok, count, dim, findings) = audit(recs, 0.999, 0.30);
            print_json(ok, count, dim, &findings);
            process::exit(if ok { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, v: Vec<f64>) -> Record {
        Record { id: id.into(), vector: v }
    }

    #[test]
    fn clean_store_ok() {
        let recs = vec![rec("a", vec![0.9, 0.1]), rec("b", vec![0.1, 0.9]), rec("c", vec![0.4, 0.6])];
        let (ok, count, dim, f) = audit(recs, 0.999, 0.30);
        assert!(ok);
        assert_eq!(count, 3);
        assert_eq!(dim, 2);
        assert!(f.iter().all(|x| x.severity != "critical"));
    }

    #[test]
    fn zero_vector_critical() {
        let recs = vec![rec("a", vec![1.0, 0.0]), rec("z", vec![0.0, 0.0]), rec("b", vec![0.0, 1.0])];
        let (ok, _, _, f) = audit(recs, 0.999, 0.30);
        assert!(!ok);
        assert!(f.iter().any(|x| x.code == "ZERO_VECTOR"));
    }

    #[test]
    fn dim_mismatch() {
        let recs = vec![rec("a", vec![1.0, 0.0]), rec("b", vec![0.0, 1.0, 0.0])];
        let (_, _, _, f) = audit(recs, 0.999, 0.30);
        assert!(f.iter().any(|x| x.code == "DIM_MISMATCH"));
    }

    #[test]
    fn duplicate_detected() {
        let recs = vec![rec("a", vec![0.5, 0.5]), rec("b", vec![0.5, 0.5]), rec("c", vec![0.1, 0.9])];
        let (_, _, _, f) = audit(recs, 0.999, 0.30);
        assert!(f.iter().any(|x| x.code == "DUPLICATE_VECTOR"));
    }

    #[test]
    fn retrieval_domination() {
        let mut recs: Vec<Record> = (0..6).map(|i| rec(&format!("p{}", i), vec![0.5 + i as f64 * 1e-4, 0.5, 0.5])).collect();
        recs.push(rec("x", vec![0.9, 0.1, 0.0]));
        recs.push(rec("y", vec![0.0, 0.1, 0.9]));
        let (ok, _, _, f) = audit(recs, 0.999, 0.30);
        assert!(!ok);
        assert!(f.iter().any(|x| x.code == "RETRIEVAL_DOMINATION"));
    }

    #[test]
    fn parse_vector_and_id() {
        let line = "{\"id\": \"abc\", \"vector\": [1.0, 2.5, -3.0], \"text\": \"hi\"}";
        assert_eq!(extract_str(line, "id").unwrap(), "abc");
        assert_eq!(extract_vector(line).unwrap(), vec![1.0, 2.5, -3.0]);
    }
}
