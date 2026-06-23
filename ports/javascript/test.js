// Smoke tests for the JavaScript port. Node built-in test runner, no deps:
//   node --test ports/javascript/test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import { audit, loadJsonl } from "./index.js";

const rec = (id, vector) => ({ id, vector, text: "" });
const codes = (f) => f.map((x) => x.code);

test("clean store is ok", () => {
  const r = audit([rec("a", [0.9, 0.1]), rec("b", [0.1, 0.9]), rec("c", [0.4, 0.6])]);
  assert.equal(r.ok, true);
  assert.equal(r.record_count, 3);
  assert.equal(r.dimension, 2);
});

test("zero vector is critical", () => {
  const r = audit([rec("a", [1, 0]), rec("z", [0, 0]), rec("b", [0, 1])]);
  assert.equal(r.ok, false);
  assert.ok(codes(r.findings).includes("ZERO_VECTOR"));
});

test("dimension mismatch", () => {
  const r = audit([rec("a", [1, 0]), rec("b", [0, 1, 0])]);
  assert.ok(codes(r.findings).includes("DIM_MISMATCH"));
});

test("duplicate detected", () => {
  const r = audit([rec("a", [0.5, 0.5]), rec("b", [0.5, 0.5]), rec("c", [0.1, 0.9])]);
  assert.ok(codes(r.findings).includes("DUPLICATE_VECTOR"));
});

test("retrieval domination is critical", () => {
  const recs = [];
  for (let i = 0; i < 6; i++) recs.push(rec(`p${i}`, [0.5 + i * 1e-4, 0.5, 0.5]));
  recs.push(rec("x", [0.9, 0.1, 0.0]), rec("y", [0.0, 0.1, 0.9]));
  const r = audit(recs);
  assert.equal(r.ok, false);
  assert.ok(codes(r.findings).includes("RETRIEVAL_DOMINATION"));
});

test("loadJsonl parses records and rejects bad input", () => {
  const recs = loadJsonl('{"id":"a","vector":[1,0]}\n{"id":"b","vector":[0,1]}\n');
  assert.equal(recs.length, 2);
  assert.equal(recs[0].id, "a");
  assert.throws(() => loadJsonl('{"id":"a","vector":"nope"}'));
  assert.throws(() => loadJsonl(""));
});

test("loadJsonl + audit on a poisoned fixture exits non-ok", () => {
  const recs = [];
  for (let i = 0; i < 5; i++) recs.push(rec(`poison-${i}`, [0.3 + i * 1e-5, 0.3, 0.3, 0.84]));
  recs.push(rec("clean-1", [0.91, 0.1, 0.05, 0.02]));
  recs.push(rec("broken-1", [0, 0, 0, 0]));
  const r = audit(recs);
  assert.equal(r.ok, false);
});
