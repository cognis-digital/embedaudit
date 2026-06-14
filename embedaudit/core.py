"""Core audit engine for EMBEDAUDIT.

Pure standard library. All vector math is implemented by hand so the tool has
zero dependencies and runs anywhere Python 3.10+ runs.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field, asdict
from typing import Any


class AuditError(Exception):
    """Raised on unrecoverable input problems."""


@dataclass
class Record:
    id: str
    vector: list[float]
    text: str = ""


@dataclass
class Finding:
    severity: str  # "critical" | "warning" | "info"
    code: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditResult:
    record_count: int = 0
    dimension: int | None = None
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not any(f.severity == "critical" for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "record_count": self.record_count,
            "dimension": self.dimension,
            "stats": self.stats,
            "findings": [asdict(f) for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def load_jsonl(path: str) -> list[Record]:
    """Load embedding records from a JSONL file."""
    records: list[Record] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise AuditError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            if not isinstance(obj, dict):
                raise AuditError(f"{path}:{lineno}: line is not a JSON object")
            if "vector" not in obj:
                raise AuditError(f"{path}:{lineno}: missing 'vector' field")
            vec = obj["vector"]
            if not isinstance(vec, list) or not all(
                isinstance(x, (int, float)) for x in vec
            ):
                raise AuditError(f"{path}:{lineno}: 'vector' must be a list of numbers")
            rid = str(obj.get("id", f"line-{lineno}"))
            records.append(Record(id=rid, vector=[float(x) for x in vec],
                                  text=str(obj.get("text", ""))))
    if not records:
        raise AuditError(f"{path}: no records loaded")
    return records


# --------------------------------------------------------------------------- #
# Vector math
# --------------------------------------------------------------------------- #

def _norm(v: list[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def _dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _cosine(a: list[float], b: list[float], na: float, nb: float) -> float:
    if na == 0.0 or nb == 0.0:
        return 0.0
    return _dot(a, b) / (na * nb)


def _mean_vector(vectors: list[list[float]], dim: int) -> list[float]:
    acc = [0.0] * dim
    for v in vectors:
        for i in range(dim):
            acc[i] += v[i]
    n = len(vectors)
    return [x / n for x in acc]


def _quantize_key(v: list[float], buckets: int = 1000) -> tuple[int, ...] | None:
    """Coarse hash for exact/near-duplicate detection via bucketed coords.

    Returns None if the vector contains NaN or Inf values (those are already
    flagged as INVALID_VALUE and must be excluded from duplicate detection).
    """
    try:
        return tuple(int(round(x * buckets)) for x in v)
    except (ValueError, OverflowError):
        return None


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #

def audit_store(
    records: list[Record],
    *,
    dup_threshold: float = 0.999,
    outlier_z: float = 3.0,
    norm_z: float = 4.0,
    domination_share: float = 0.30,
) -> AuditResult:
    """Audit a single embedding store snapshot for integrity + poisoning."""
    if not records:
        raise AuditError("audit_store requires at least one record")
    res = AuditResult(record_count=len(records))

    # --- dimension consistency ---
    dims = {len(r.vector) for r in records}
    if len(dims) != 1:
        counts: dict[int, int] = {}
        for r in records:
            counts[len(r.vector)] = counts.get(len(r.vector), 0) + 1
        res.findings.append(Finding(
            "critical", "DIM_MISMATCH",
            f"Inconsistent vector dimensions: {sorted(dims)}",
            {"dimension_counts": counts},
        ))
        # use majority dimension for what follows
        dim = max(counts, key=counts.get)
        records = [r for r in records if len(r.vector) == dim]
    else:
        dim = dims.pop()
    res.dimension = dim

    # --- norms + invalid values ---
    norms: list[float] = []
    for r in records:
        if any(math.isnan(x) or math.isinf(x) for x in r.vector):
            res.findings.append(Finding(
                "critical", "INVALID_VALUE",
                f"Vector '{r.id}' contains NaN/Inf",
                {"id": r.id},
            ))
        norms.append(_norm(r.vector))

    n = len(records)
    mean_norm = sum(norms) / n
    var_norm = sum((x - mean_norm) ** 2 for x in norms) / n
    std_norm = math.sqrt(var_norm)

    zero_norm = [records[i].id for i in range(n) if norms[i] == 0.0]
    if zero_norm:
        res.findings.append(Finding(
            "critical", "ZERO_VECTOR",
            f"{len(zero_norm)} zero-norm vector(s) (un-embeddable / corrupt)",
            {"ids": zero_norm[:20]},
        ))

    if std_norm > 0:
        for i in range(n):
            z = (norms[i] - mean_norm) / std_norm
            if abs(z) >= norm_z:
                res.findings.append(Finding(
                    "warning", "NORM_OUTLIER",
                    f"Vector '{records[i].id}' norm z-score {z:.2f} "
                    f"(possible mis-scaled / different model)",
                    {"id": records[i].id, "norm": norms[i], "z": z},
                ))

    # --- exact/near duplicate detection ---
    seen: dict[tuple[int, ...], str] = {}
    exact_dups: list[tuple[str, str]] = []
    for r in records:
        key = _quantize_key(r.vector)
        if key is None:  # NaN/Inf vector — already flagged as INVALID_VALUE
            continue
        if key in seen:
            exact_dups.append((seen[key], r.id))
        else:
            seen[key] = r.id
    if exact_dups:
        res.findings.append(Finding(
            "warning", "DUPLICATE_VECTOR",
            f"{len(exact_dups)} duplicate vector pair(s) detected (index bloat "
            f"/ retrieval flooding)",
            {"pairs": exact_dups[:20]},
        ))

    # --- centroid + outlier / domination analysis ---
    vectors = [r.vector for r in records]
    centroid = _mean_vector(vectors, dim)
    c_norm = _norm(centroid)

    sims_to_centroid: list[float] = []
    for i in range(n):
        sims_to_centroid.append(_cosine(vectors[i], centroid, norms[i], c_norm))

    mean_sim = sum(sims_to_centroid) / n
    var_sim = sum((s - mean_sim) ** 2 for s in sims_to_centroid) / n
    std_sim = math.sqrt(var_sim)

    if std_sim > 0:
        for i in range(n):
            z = (sims_to_centroid[i] - mean_sim) / std_sim
            if z <= -outlier_z:
                res.findings.append(Finding(
                    "warning", "OUTLIER_VECTOR",
                    f"Vector '{records[i].id}' is a far outlier "
                    f"(z={z:.2f} vs centroid)",
                    {"id": records[i].id, "z": z},
                ))

    # --- domination: a tight cluster near-identical to a large share of the
    #     store can hijack top-k retrieval (universal poison docs). ---
    clusters = _greedy_clusters(vectors, norms, dup_threshold)
    largest = max(clusters, key=len) if clusters else []
    share = len(largest) / n if n else 0.0
    if share >= domination_share and len(largest) > 1:
        ids = [records[i].id for i in largest]
        res.findings.append(Finding(
            "critical", "RETRIEVAL_DOMINATION",
            f"{len(largest)} near-identical vectors form {share:.0%} of the "
            f"store (retrieval-domination / poisoning risk)",
            {"ids": ids[:20], "share": share},
        ))

    res.stats = {
        "mean_norm": mean_norm,
        "std_norm": std_norm,
        "min_norm": min(norms),
        "max_norm": max(norms),
        "mean_centroid_sim": mean_sim,
        "duplicate_pairs": len(exact_dups),
        "largest_cluster": len(largest),
        "largest_cluster_share": share,
        "num_clusters": len(clusters),
    }
    return res


def _greedy_clusters(
    vectors: list[list[float]], norms: list[float], threshold: float
) -> list[list[int]]:
    """Single-pass greedy clustering by cosine similarity to cluster heads.

    O(n * k) where k = number of clusters. Adequate for audit-scale snapshots.
    """
    heads: list[int] = []
    clusters: list[list[int]] = []
    for i, v in enumerate(vectors):
        placed = False
        for hi, head in enumerate(heads):
            if _cosine(v, vectors[head], norms[i], norms[head]) >= threshold:
                clusters[hi].append(i)
                placed = True
                break
        if not placed:
            heads.append(i)
            clusters.append([i])
    return clusters


# --------------------------------------------------------------------------- #
# Drift
# --------------------------------------------------------------------------- #

def drift_report(
    baseline: list[Record],
    current: list[Record],
    *,
    drift_threshold: float = 0.15,
) -> AuditResult:
    """Compare a trusted baseline snapshot against a current snapshot.

    Drift = cosine distance between the two centroids plus the fraction of
    dimensions whose mean shifted beyond `drift_threshold` (normalised). A
    high drift score on an embedding store that should be append-only is a
    strong poisoning / silent-model-swap signal.
    """
    res = AuditResult(record_count=len(current))

    bdim = {len(r.vector) for r in baseline}
    cdim = {len(r.vector) for r in current}
    if len(bdim) != 1 or len(cdim) != 1:
        res.findings.append(Finding(
            "critical", "DIM_MISMATCH",
            "Snapshot(s) have inconsistent internal dimensions",
            {"baseline_dims": sorted(bdim), "current_dims": sorted(cdim)},
        ))
        return res
    bd, cd = bdim.pop(), cdim.pop()
    if bd != cd:
        res.findings.append(Finding(
            "critical", "DIM_MISMATCH",
            f"Baseline dim {bd} != current dim {cd} (model changed)",
            {"baseline_dim": bd, "current_dim": cd},
        ))
        return res
    dim = bd
    res.dimension = dim

    bcent = _mean_vector([r.vector for r in baseline], dim)
    ccent = _mean_vector([r.vector for r in current], dim)
    bn, cn = _norm(bcent), _norm(ccent)
    centroid_dist = 1.0 - _cosine(bcent, ccent, bn, cn)

    # per-dimension normalised shift
    spread = max((abs(x) for x in bcent), default=1.0) or 1.0
    shifts = [abs(ccent[i] - bcent[i]) / spread for i in range(dim)]
    drifted_dims = [i for i, s in enumerate(shifts) if s >= drift_threshold]
    frac_drifted = len(drifted_dims) / dim

    drift_score = 0.5 * centroid_dist + 0.5 * frac_drifted

    severity = "info"
    if drift_score >= 0.30:
        severity = "critical"
    elif drift_score >= drift_threshold:
        severity = "warning"

    res.findings.append(Finding(
        severity, "DRIFT",
        f"Drift score {drift_score:.3f} "
        f"(centroid_dist={centroid_dist:.3f}, dims_drifted={frac_drifted:.0%})",
        {
            "drift_score": drift_score,
            "centroid_distance": centroid_dist,
            "fraction_dims_drifted": frac_drifted,
            "top_drifted_dims": sorted(
                ((i, shifts[i]) for i in drifted_dims),
                key=lambda t: t[1], reverse=True,
            )[:10],
        },
    ))

    bcount, ccount = len(baseline), len(current)
    if ccount < bcount:
        res.findings.append(Finding(
            "warning", "RECORD_LOSS",
            f"Current snapshot has fewer records ({ccount}) than baseline "
            f"({bcount}) - possible deletion / truncation",
            {"baseline": bcount, "current": ccount},
        ))

    res.stats = {
        "drift_score": drift_score,
        "centroid_distance": centroid_dist,
        "fraction_dims_drifted": frac_drifted,
        "baseline_records": bcount,
        "current_records": ccount,
    }
    return res
