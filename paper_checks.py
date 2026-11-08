"""Verify the submitted paper’s numerical results and export figure data."""
import csv
import hashlib
import json
import math
from pathlib import Path
from xml.etree import ElementTree as ET

from backport import cisa, write_rows
from egovframe_priority_reproduce import CASES, analyse, supplier_result
from egovframe_priority_review import public_pairs, provisional_product

ROOT = Path(__file__).resolve().parent
SOURCES = ROOT / "sources"


def read_json(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def read_csv(path):
    with (ROOT / path).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def check_sources():
    snapshot = read_json("sources/snapshot_manifest.json")
    assert len(list((SOURCES / "ghsa").glob("*.json"))) == snapshot["ghsa_scope_records_saved"] == 145
    assert len(list((SOURCES / "cve").glob("*.json"))) == len(snapshot["cve_records"]) == 145
    for record in snapshot["cve_records"]:
        raw = (SOURCES / "cve" / f"{record['cve']}.json").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == record["sha256"], record["cve"]
    table = (SOURCES / "supplier_patch_development_priority_1_0_0.csv").read_bytes()
    assert hashlib.sha256(table).hexdigest() == snapshot["ssvc_table"]["sha256"]
    evidence = read_json("public_ssvc_evidence.json")
    for record in evidence["records"]:
        expected, timestamp = cisa(record["id"])
        actual = record["values"]
        assert (not expected and not actual) or (
            len(actual) == 1 and actual[0]["timestamp"] == timestamp and
            {k: v for pair in actual[0]["options"] for k, v in pair.items()} == expected
        ), record["id"]
    pom_specs = {
        "MVC-4.0.0": ("spring-webmvc", "5.3.6"),
        "MongoDB-4.1.0": ("spring-data-mongodb", "3.4.0"),
        "MVC-4.3.0": ("spring-webmvc", "5.3.37"),
    }
    for name, (artifact, expected) in pom_specs.items():
        info = read_json("sources/case_pom_sources.json")[name]
        raw = (ROOT / info["file"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == info["sha256"]
        doc = ET.fromstring(raw)
        dependency = next(dep for dep in doc.findall("./{*}dependencies/{*}dependency")
                          if dep.findtext("{*}artifactId") == artifact)
        version = dependency.findtext("{*}version")
        if version.startswith("${") and version.endswith("}"):
            version = doc.findtext("./{*}properties/{*}" + version[2:-1])
        assert version == expected, (name, version, expected)


def check_case():
    public = {
        "CVE-2022-22965": ({"OI", "II"}, "I"),
        "CVE-2022-22980": ({"SO", "SI", "OI"}, "I"),
        "CVE-2024-38816": ({"SO"}, "O"),
    }
    for cve, (pairs, action) in public.items():
        actual = public_pairs(cve)
        assert set(actual) == pairs, cve
        assert provisional_product(actual, True, False, None) == action, cve

    case = CASES["CVE-2024-38816"]
    known = case["known"]
    unknown_gates = {site: [f"{site}.{g}" for g in case["gates"] if f"{site}.{g}" not in known]
                     for site in ("A", "B")}
    assert [len(x) for x in unknown_gates.values()] == [2, 3]
    # In the paper's example, A fails the filesystem condition and B's path holds.
    assert unknown_gates["A"][0] == "A.filesystem"
    replies = known | {k: False for k in unknown_gates["A"]} | {k: True for k in unknown_gates["B"]}
    replies |= {"A.safety_evidence": False, "B.safety_evidence": False}
    assert supplier_result(case, replies, "SO") == "S"
    assert supplier_result(case, replies | {"B.safety_evidence": True}, "SO") == "O"
    before_b_harm = {k: v for k, v in replies.items() if k != "B.safety_evidence"}
    assert {supplier_result(case, before_b_harm | {"B.safety_evidence": v}, "SO") for v in (False, True)} == {"S", "O"}
    seq = 1 + len(unknown_gates["B"]) + 1
    parallel = sum(map(len, unknown_gates.values())) + 1
    batch = analyse(case, "SO")["fixed_fields"]
    assert (seq, parallel, batch) == (5, 6, 7)
    write_rows(ROOT / "paper_case_trace.csv", [
        {"policy": "serial", "checks": seq, "rounds": seq},
        {"policy": "two_stage_parallel", "checks": parallel, "rounds": 2},
        {"policy": "batch", "checks": batch, "rounds": 1},
    ])


def check_paper_numbers():
    summary = read_json("advisory_audit_summary.json")
    for scope, values in {"all": (47, 14, 43), "direct": (26, 7, 23),
                          "expanded_scope": (40, 13, 36), "technical_high": (17, 9, 13),
                          "technical_other": (30, 5, 30)}.items():
        row = summary[scope]
        assert (row["n"], row["backport"], row["sensitive_concentrated"]) == values, scope
    assert summary["provisional_concentrated"] == {"out-of-cycle": 47}
    assert summary["provisional_diffuse"] == {"out-of-cycle": 17, "scheduled": 30}
    assert len(summary["out_of_cycle_regardless_of_safety_outside_notice"]) == 3
    selected = read_json("backport_summary.json")
    assert selected["official_backport_cves_outside_population"] == ["CVE-2026-59324"]
    sensitivity = read_csv("exploitation_sensitivity.csv")
    assert [int(x["safety_sensitive"]) for x in sensitivity] == [43, 47, 47, 47, 34, 47]
    assert int(sensitivity[4]["same_immediate"]) == 13
    base = read_csv("egovframe_priority_results.csv")
    assert len(base) == 54
    rows = read_csv("egovframe_priority_sensitivity.csv")
    assert len(rows) == 108
    assert max(abs(float(x["serial_prerequisite_gap"])) for x in rows) < 1e-12
    lambdas = read_csv("lambda_results.csv")
    file_case = next(x for x in lambdas if x["conditions"] == "2,3" and x["sensitive"] == "1")
    prefixes = ("full_batch", "filtered_batch", "serial", "grouped", "parallel")
    # Compare unrounded means with the values printed to two decimal places.
    assert all(math.isclose(float(file_case[k + "_checks"]), checks, abs_tol=0.0051)
               and math.isclose(float(file_case[k + "_rounds"]), rounds, abs_tol=0.0051)
               for k, (checks, rounds) in zip(prefixes, ((7,1),(7,1),(3.39,3.39),(4.98,2.23),(5.38,1.34))))
    assert round(float(file_case["lambda_serial_parallel"]),2) == .97
    assert round(float(file_case["lambda_parallel_batch"]),2) == 4.73
    first = [float(x["lambda_serial_parallel"]) for x in lambdas[:4]]
    second = [float(x["lambda_parallel_batch"]) for x in lambdas[:4] if x["lambda_parallel_batch"]]
    assert (round(min(first),2),round(max(first),2),round(min(second),2),round(max(second),2)) == (.97,1.21,4.73,7.47)
    ten = lambdas[-1]
    assert ten["conditions"] == ",".join(["3"] * 10)
    keys = ("serial_checks","serial_rounds","parallel_checks","parallel_rounds","lambda_serial_parallel","lambda_parallel_batch")
    assert tuple(round(float(ten[k]),2) for k in keys) == (14.27,14.27,31.25,1.74,1.36,11.87)
    plot = []
    low, high = (float(file_case[k]) for k in ("lambda_serial_parallel", "lambda_parallel_batch"))
    for x in sorted({i / 10 for i in range(71)} | {low, high}):
        costs = {k: float(file_case[k + "_checks"]) + x * float(file_case[k + "_rounds"])
                 for k in ("serial", "parallel", "full_batch", "grouped")}
        winners = ";".join(k for k, cost in costs.items() if math.isclose(cost, min(costs.values()), abs_tol=1e-12))
        plot.append({"lambda": x, **costs, "minimum_cost": min(costs.values()), "minimizers": winners})
    write_rows(ROOT / "paper_figure4_points.csv", plot)


if __name__ == "__main__":
    check_sources()
    check_case()
    check_paper_numbers()
    print("PASS: frozen inputs, case evidence and POMs, Figure 3, Table 3 trace, Table 4, Figure 4, and 108 constrained comparisons")
