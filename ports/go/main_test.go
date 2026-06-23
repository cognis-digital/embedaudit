package main

import (
	"fmt"
	"testing"
)

func rec(id string, v []float64) record { return record{ID: id, Vector: v} }

func hasCode(f []finding, code string) bool {
	for _, x := range f {
		if x.Code == code {
			return true
		}
	}
	return false
}

func TestCleanStoreOK(t *testing.T) {
	r := audit([]record{rec("a", []float64{0.9, 0.1}), rec("b", []float64{0.1, 0.9}), rec("c", []float64{0.4, 0.6})}, 0.999, 0.30)
	if !r.OK {
		t.Fatal("clean store should be OK")
	}
	if r.RecordCount != 3 || r.Dimension != 2 {
		t.Fatalf("count/dim = %d/%d", r.RecordCount, r.Dimension)
	}
}

func TestZeroVectorCritical(t *testing.T) {
	r := audit([]record{rec("a", []float64{1, 0}), rec("z", []float64{0, 0}), rec("b", []float64{0, 1})}, 0.999, 0.30)
	if r.OK || !hasCode(r.Findings, "ZERO_VECTOR") {
		t.Fatal("expected ZERO_VECTOR critical")
	}
}

func TestDimMismatch(t *testing.T) {
	r := audit([]record{rec("a", []float64{1, 0}), rec("b", []float64{0, 1, 0})}, 0.999, 0.30)
	if !hasCode(r.Findings, "DIM_MISMATCH") {
		t.Fatal("expected DIM_MISMATCH")
	}
}

func TestDuplicateDetected(t *testing.T) {
	r := audit([]record{rec("a", []float64{0.5, 0.5}), rec("b", []float64{0.5, 0.5}), rec("c", []float64{0.1, 0.9})}, 0.999, 0.30)
	if !hasCode(r.Findings, "DUPLICATE_VECTOR") {
		t.Fatal("expected DUPLICATE_VECTOR")
	}
}

func TestRetrievalDomination(t *testing.T) {
	var recs []record
	for i := 0; i < 6; i++ {
		recs = append(recs, rec(fmt.Sprintf("p%d", i), []float64{0.5 + float64(i)*1e-4, 0.5, 0.5}))
	}
	recs = append(recs, rec("x", []float64{0.9, 0.1, 0.0}), rec("y", []float64{0.0, 0.1, 0.9}))
	r := audit(recs, 0.999, 0.30)
	if r.OK || !hasCode(r.Findings, "RETRIEVAL_DOMINATION") {
		t.Fatal("expected RETRIEVAL_DOMINATION critical")
	}
}

func TestNormAndCosine(t *testing.T) {
	if n := norm([]float64{3, 4}); n != 5 {
		t.Fatalf("norm = %v", n)
	}
	if c := cosine([]float64{1, 0}, []float64{1, 0}, 1, 1); c != 1 {
		t.Fatalf("cosine = %v", c)
	}
}
