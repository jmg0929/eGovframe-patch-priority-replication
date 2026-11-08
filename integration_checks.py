"""Compare advisory scopes and compute the lowest-cost policy as delay cost varies."""
import csv
import json
from collections import Counter
from fractions import Fraction as F
from itertools import combinations
from math import comb
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parent
POMS = ROOT / "sources" / "runtime_431_poms"
POM_COMMIT = "4fa1e27ff3a8ac44a45b78c55c822fb50e758950"


def rows(name):
    with (ROOT / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def write_csv(name, data):
    with (ROOT / name).open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(data[0]))
        writer.writeheader()
        writer.writerows(data)


def direct_modules():
    """Read compile and provided dependencies declared directly in module POMs."""
    groups = {"org.springframework", "org.springframework.security",
              "org.springframework.integration", "org.springframework.data"}
    by_package = {}
    root = ET.parse(POMS / "pom.xml")
    for module in root.findall("./{*}modules/{*}module"):
        path = POMS / module.text.strip() / "pom.xml"
        for dependency in ET.parse(path).findall("./{*}dependencies/{*}dependency"):
            group = dependency.findtext("{*}groupId")
            scope = dependency.findtext("{*}scope", "compile")
            if group in groups and scope in {"compile", "provided"}:
                artifact = dependency.findtext("{*}artifactId")
                by_package.setdefault(artifact, []).append({
                    "pom": path.relative_to(POMS).as_posix(),
                    "coordinate": f"{group}:{artifact}", "scope": scope,
                })
    return by_package


def fisher(a, b, c, d):
    n, row, col = a + b + c + d, a + b, a + c
    def mass(x):
        return comb(row, x) * comb(n - row, col - x)
    low, high = max(0, col - (n - row)), min(row, col)
    return F(sum(mass(x) for x in range(low, high + 1) if mass(x) <= mass(a)), comb(n, col))


def advisory_checks():
    population = rows("backport_population.csv")
    concentrated = {r["cve"]: r for r in rows("bridge_results.csv")}
    diffuse = {r["cve"]: r for r in rows("bridge_results_diffuse.csv")}
    evidence = {r["cve"]: r for r in json.loads((ROOT / "bridge_evidence.json").read_text(encoding="utf-8"))}
    direct = direct_modules()
    expanded = set(json.loads((ROOT / "sources/expanded_artifact_scope.json").read_text(encoding="utf-8"))["artifacts"])
    assert {x["cve"] for x in population} == set(concentrated) == set(diffuse) == set(evidence)
    data = []
    for row in population:
        cve = row["cve"]
        c, d = concentrated[cve], diffuse[cve]
        e = evidence[cve]
        assert e["complete_technical_inputs"]
        inputs = e["technical_options"]
        assert inputs["Exploitation"] == "none"
        artifacts = set(row["pkgs"].split(";"))
        matches = sorted(artifacts & direct.keys())
        expanded_matches = sorted(artifacts & expanded)
        data.append({
            "cve": cve, "ghsa": row["ghsa"], "ghsa_published": row["published"],
            "cisa_timestamp": e["cisa_timestamp"], "artifacts": row["pkgs"],
            "automatable": inputs["Automatable"], "technical_impact": inputs["Technical Impact"],
            "in_backport_notice": int(row["backported"]),
            "concentrated_minimal": c["lo"], "concentrated_significant": c["hi"],
            "diffuse_minimal": d["lo"], "diffuse_significant": d["hi"],
            "sensitive_concentrated": int(c["psi_decides"]), "sensitive_diffuse": int(d["psi_decides"]),
            "direct_compile_or_provided": int(bool(matches)), "direct_matched_artifacts": ";".join(matches),
            "expanded_scope": int(bool(expanded_matches)),
            "expanded_matched_artifacts": ";".join(expanded_matches),
        })
    write_csv("advisory_audit.csv", data)
    (ROOT / "direct_module_evidence.json").write_text(json.dumps(
        {"commit": POM_COMMIT, "artifacts": direct}, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    higher = [r for r in data if r["automatable"] == "yes" or r["technical_impact"] == "total"]
    lower = [r for r in data if r not in higher]
    def counts(subset):
        return {"n": len(subset), "backport": sum(x["in_backport_notice"] for x in subset),
                "sensitive_concentrated": sum(x["sensitive_concentrated"] for x in subset)}
    h, l = counts(higher), counts(lower)
    counts_report = {
        "all": counts(data),
        "direct": counts([r for r in data if r["direct_compile_or_provided"]]),
        "direct_sensitive": counts([r for r in data if r["direct_compile_or_provided"] and r["sensitive_concentrated"]]),
        "expanded_scope": counts([r for r in data if r["expanded_scope"]]),
        "expanded_sensitive": counts([r for r in data if r["expanded_scope"] and r["sensitive_concentrated"]]),
        "out_of_cycle_regardless_of_safety_outside_notice": sorted(
            r["cve"] for r in data if not r["in_backport_notice"]
            and r["concentrated_minimal"] == r["concentrated_significant"] == "out-of-cycle"
        ),
        "technical_high": h, "technical_other": l,
        "fisher_two_sided": float(fisher(h["backport"], h["n"] - h["backport"], l["backport"], l["n"] - l["backport"])),
        "provisional_concentrated": dict(Counter(r["concentrated_significant"] for r in data)),
        "provisional_diffuse": dict(Counter(r["diffuse_significant"] for r in data)),
        "cisa_first": min(r["cisa_timestamp"] for r in data),
        "cisa_last": max(r["cisa_timestamp"] for r in data),
    }
    (ROOT / "advisory_audit_summary.json").write_text(json.dumps(counts_report, indent=2), encoding="utf-8", newline="\n")
    print(json.dumps(counts_report, indent=2))


def policy_lines(conditions, sensitive):
    # Each policy has cost E[checks] + lambda * E[rounds] under the uniform model.
    p = s = F(1, 2)
    survival, serial, grouped_checks, grouped_rounds = F(1), F(0), F(0), F(0)
    no_paths = F(1)
    for k in sorted(conditions):
        path_probability = p ** k
        possible_harm_check = path_probability if sensitive else F(0)
        serial += survival * (sum(p ** j for j in range(k)) + possible_harm_check)
        grouped_checks += survival * (k + possible_harm_check)
        grouped_rounds += survival * (1 + possible_harm_check)
        survival *= 1 - path_probability * (s if sensitive else 1)
        no_paths *= 1 - path_probability
    gates = sum(conditions)
    all_items = gates + len(conditions)
    return {
        "serial": (serial, serial),
        "parallel": (gates + sum((p ** k for k in conditions), F(0)) if sensitive else F(gates),
                     2 - no_paths if sensitive else F(1)),
        "full_batch": (F(all_items), F(1)),
        "filtered_batch": (F(all_items if sensitive else gates), F(1)),
        "grouped": (grouped_checks, grouped_rounds),
    }


def intersection(line1, line2):
    a, b = line1
    c, d = line2
    return (c - a) / (b - d) if b != d else None


def lambda_checks():
    records = []
    for ks, sensitive in [((3, 3), False), ((3, 3), True), ((2, 3), False),
                          ((2, 3), True), ((3,) * 10, True)]:
        lines = policy_lines(ks, sensitive)
        # Check each intersection and one point in each interval of constant ordering.
        critical = sorted({F(0)} | {t for a, b in combinations(lines.values(), 2)
                                    if (t := intersection(a, b)) is not None and t >= 0})
        probes = critical + [(a + b) / 2 for a, b in zip(critical, critical[1:])] + [critical[-1] + 1]
        def winners(weight):
            costs = {k: a + weight * b for k, (a, b) in lines.items()}
            return {k for k, v in costs.items() if v == min(costs.values())}
        low = intersection(lines["serial"], lines["parallel"])
        high = intersection(lines["parallel"], lines["filtered_batch"])
        assert low > 0 and (high is None or high > low)
        assert all("grouped" not in winners(x) for x in probes)
        for x in probes:
            expected = {"serial"} if x <= low else set()
            if x >= low and (high is None or x <= high):
                expected |= {"parallel"} if sensitive else {"parallel", "filtered_batch"}
            if high is not None and x >= high:
                expected |= {"filtered_batch", "full_batch"}
            assert winners(x) == expected, (ks, sensitive, x)
        records.append({"conditions": ",".join(map(str, ks)), "sensitive": int(sensitive),
                        **{f"{name}_{field}": float(value) for name, pair in lines.items()
                           for field, value in zip(("checks", "rounds"), pair)},
                        "lambda_serial_parallel": float(low),
                        "lambda_parallel_batch": "" if high is None else float(high)})
    write_csv("lambda_results.csv", records)
    print("Verified all nonnegative λ regions and intersections across five modeled structures.")


if __name__ == "__main__":
    advisory_checks()
    lambda_checks()
