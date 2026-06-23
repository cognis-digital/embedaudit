// Go port of the embedaudit core: audit a JSONL embedding snapshot for
// integrity + poisoning. Single binary, standard library only. Mirrors the
// Python reference rule IDs (ZERO_VECTOR, DIM_MISMATCH, DUPLICATE_VECTOR,
// RETRIEVAL_DOMINATION, INVALID_VALUE) and the JSON output shape.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
)

type record struct {
	ID     string    `json:"id"`
	Vector []float64 `json:"vector"`
	Text   string    `json:"text"`
}

type finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type result struct {
	OK          bool      `json:"ok"`
	RecordCount int       `json:"record_count"`
	Dimension   int       `json:"dimension"`
	Findings    []finding `json:"findings"`
}

func norm(v []float64) float64 {
	s := 0.0
	for _, x := range v {
		s += x * x
	}
	return math.Sqrt(s)
}

func cosine(a, b []float64, na, nb float64) float64 {
	if na == 0 || nb == 0 {
		return 0
	}
	d := 0.0
	for i := range a {
		d += a[i] * b[i]
	}
	return d / (na * nb)
}

func quantKey(v []float64) string {
	b := make([]byte, 0, len(v)*8)
	for _, x := range v {
		b = append(b, []byte(fmt.Sprintf("%d,", int(math.Round(x*1000))))...)
	}
	return string(b)
}

func loadJSONL(path string) ([]record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var recs []record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("%s:%d: invalid JSON", path, ln)
		}
		if r.Vector == nil {
			return nil, fmt.Errorf("%s:%d: missing 'vector'", path, ln)
		}
		if r.ID == "" {
			r.ID = fmt.Sprintf("line-%d", ln)
		}
		recs = append(recs, r)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("%s: no records loaded", path)
	}
	return recs, nil
}

func audit(recs []record, dupThreshold, dominationShare float64) result {
	res := result{RecordCount: len(recs)}

	// dimension consistency
	dimCount := map[int]int{}
	for _, r := range recs {
		dimCount[len(r.Vector)]++
	}
	dim, best := 0, -1
	for d, c := range dimCount {
		if c > best {
			best, dim = c, d
		}
	}
	if len(dimCount) != 1 {
		res.Findings = append(res.Findings, finding{"critical", "DIM_MISMATCH",
			"Inconsistent vector dimensions"})
		kept := recs[:0]
		for _, r := range recs {
			if len(r.Vector) == dim {
				kept = append(kept, r)
			}
		}
		recs = kept
	}
	res.Dimension = dim

	// norms, zero vectors, invalid values
	norms := make([]float64, len(recs))
	var zero []string
	for i, r := range recs {
		for _, x := range r.Vector {
			if math.IsNaN(x) || math.IsInf(x, 0) {
				res.Findings = append(res.Findings, finding{"critical",
					"INVALID_VALUE", "Vector '" + r.ID + "' contains NaN/Inf"})
				break
			}
		}
		norms[i] = norm(r.Vector)
		if norms[i] == 0 {
			zero = append(zero, r.ID)
		}
	}
	if len(zero) > 0 {
		res.Findings = append(res.Findings, finding{"critical", "ZERO_VECTOR",
			fmt.Sprintf("%d zero-norm vector(s) (un-embeddable / corrupt)", len(zero))})
	}

	// duplicates
	seen := map[string]bool{}
	dups := 0
	for _, r := range recs {
		k := quantKey(r.Vector)
		if seen[k] {
			dups++
		} else {
			seen[k] = true
		}
	}
	if dups > 0 {
		res.Findings = append(res.Findings, finding{"warning", "DUPLICATE_VECTOR",
			fmt.Sprintf("%d duplicate vector pair(s) detected", dups)})
	}

	// greedy clustering -> retrieval domination
	var heads []int
	clusters := map[int][]int{}
	for i := range recs {
		placed := false
		for _, h := range heads {
			if cosine(recs[i].Vector, recs[h].Vector, norms[i], norms[h]) >= dupThreshold {
				clusters[h] = append(clusters[h], i)
				placed = true
				break
			}
		}
		if !placed {
			heads = append(heads, i)
			clusters[i] = []int{i}
		}
	}
	largest := 0
	for _, c := range clusters {
		if len(c) > largest {
			largest = len(c)
		}
	}
	share := 0.0
	if len(recs) > 0 {
		share = float64(largest) / float64(len(recs))
	}
	if share >= dominationShare && largest > 1 {
		res.Findings = append(res.Findings, finding{"critical", "RETRIEVAL_DOMINATION",
			fmt.Sprintf("%d near-identical vectors form %.0f%% of the store", largest, share*100)})
	}

	res.OK = true
	for _, f := range res.Findings {
		if f.Severity == "critical" {
			res.OK = false
		}
	}
	return res
}

func main() {
	if len(os.Args) < 3 || os.Args[1] != "audit" {
		fmt.Fprintln(os.Stderr, "usage: embedaudit audit <snapshot.jsonl>")
		os.Exit(2)
	}
	recs, err := loadJSONL(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	res := audit(recs, 0.999, 0.30)
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if !res.OK {
		os.Exit(1)
	}
}
