#!/usr/bin/env node
// JavaScript / Node port of the embedaudit core: audit a JSONL embedding
// snapshot for integrity + poisoning. Standard library only. Mirrors the
// Python reference rule IDs and JSON output shape.
import { readFileSync } from "fs";
import { pathToFileURL } from "url";

const DUP_THRESHOLD = 0.999;
const DOMINATION_SHARE = 0.30;

function norm(v) {
  let s = 0;
  for (const x of v) s += x * x;
  return Math.sqrt(s);
}

function cosine(a, b, na, nb) {
  if (na === 0 || nb === 0) return 0;
  let d = 0;
  for (let i = 0; i < a.length; i++) d += a[i] * b[i];
  return d / (na * nb);
}

function quantKey(v) {
  return v.map((x) => Math.round(x * 1000)).join(",");
}

export function loadJsonl(text) {
  const recs = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      throw new Error(`line ${i + 1}: invalid JSON`);
    }
    if (!obj || typeof obj !== "object" || !Array.isArray(obj.vector))
      throw new Error(`line ${i + 1}: missing or invalid 'vector'`);
    if (!obj.vector.every((x) => typeof x === "number"))
      throw new Error(`line ${i + 1}: 'vector' must be numbers`);
    recs.push({
      id: String(obj.id ?? `line-${i + 1}`),
      vector: obj.vector,
      text: String(obj.text ?? ""),
    });
  }
  if (recs.length === 0) throw new Error("no records loaded");
  return recs;
}

export function audit(recs, dupThreshold = DUP_THRESHOLD, dominationShare = DOMINATION_SHARE) {
  const findings = [];

  // dimension consistency
  const dimCount = new Map();
  for (const r of recs) dimCount.set(r.vector.length, (dimCount.get(r.vector.length) || 0) + 1);
  let dim = 0, best = -1;
  for (const [d, c] of dimCount) if (c > best) { best = c; dim = d; }
  if (dimCount.size !== 1) {
    findings.push({ severity: "critical", code: "DIM_MISMATCH", message: "Inconsistent vector dimensions" });
    recs = recs.filter((r) => r.vector.length === dim);
  }

  // norms, zero vectors, invalid values
  const norms = [];
  const zero = [];
  for (const r of recs) {
    if (r.vector.some((x) => Number.isNaN(x) || !Number.isFinite(x)))
      findings.push({ severity: "critical", code: "INVALID_VALUE", message: `Vector '${r.id}' contains NaN/Inf` });
    const n = norm(r.vector);
    norms.push(n);
    if (n === 0) zero.push(r.id);
  }
  if (zero.length)
    findings.push({ severity: "critical", code: "ZERO_VECTOR", message: `${zero.length} zero-norm vector(s) (un-embeddable / corrupt)` });

  // duplicates
  const seen = new Set();
  let dups = 0;
  for (const r of recs) {
    const k = quantKey(r.vector);
    if (seen.has(k)) dups++; else seen.add(k);
  }
  if (dups)
    findings.push({ severity: "warning", code: "DUPLICATE_VECTOR", message: `${dups} duplicate vector pair(s) detected` });

  // greedy clustering -> retrieval domination
  const heads = [];
  const clusters = [];
  for (let i = 0; i < recs.length; i++) {
    let placed = false;
    for (let h = 0; h < heads.length; h++) {
      if (cosine(recs[i].vector, recs[heads[h]].vector, norms[i], norms[heads[h]]) >= dupThreshold) {
        clusters[h].push(i); placed = true; break;
      }
    }
    if (!placed) { heads.push(i); clusters.push([i]); }
  }
  const largest = clusters.reduce((m, c) => Math.max(m, c.length), 0);
  const share = recs.length ? largest / recs.length : 0;
  if (share >= dominationShare && largest > 1)
    findings.push({ severity: "critical", code: "RETRIEVAL_DOMINATION", message: `${largest} near-identical vectors form ${Math.round(share * 100)}% of the store` });

  const ok = !findings.some((f) => f.severity === "critical");
  return { ok, record_count: recs.length, dimension: dim, findings };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [cmd, path] = process.argv.slice(2);
  if (cmd !== "audit" || !path) {
    console.error("usage: embedaudit audit <snapshot.jsonl>");
    process.exit(2);
  }
  let res;
  try {
    res = audit(loadJsonl(readFileSync(path, "utf8")));
  } catch (e) {
    console.error("error:", e.message);
    process.exit(2);
  }
  console.log(JSON.stringify(res, null, 2));
  process.exit(res.ok ? 0 : 1);
}
