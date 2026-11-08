"""Evaluate sensitivity to assumed exploitation and to the unit of a request."""
from collections import Counter
from itertools import product
import json

from backport import ROOT, write_rows
from bridge import table
from analysis_helpers import utility
from egovframe_priority_reproduce import CASES
from egovframe_priority_review import compare


def exploitation_sensitivity():
    decision = table()
    evidence = json.loads((ROOT / "bridge_evidence.json").read_text(encoding="utf-8"))
    assert len(evidence) == 47
    assert all(r["technical_options"]["Exploitation"] == "none" for r in evidence)
    # Vary exploitation and value density while retaining the other CISA-ADP inputs.
    records = []
    for state, density in product(("none", "public poc", "active"), ("concentrated", "diffuse")):
        pairs = Counter()
        for r in evidence:
            tech = r["technical_options"]
            u = utility(tech["Automatable"], density)
            outcomes = tuple(decision[state, u, tech["Technical Impact"], safety]
                             for safety in ("minimal", "significant"))
            pairs[outcomes] += 1
        records.append({
            "exploitation": state, "source": "snapshot" if state == "none" else "hypothetical",
            "value_density": density, "n": len(evidence),
            "safety_sensitive": sum(n for (a, b), n in pairs.items() if a != b),
            "same_immediate": pairs["immediate", "immediate"],
            "pair_counts": json.dumps({f"{a} → {b}": n for (a, b), n in sorted(pairs.items())}, ensure_ascii=False),
        })
    write_rows(ROOT / "exploitation_sensitivity.csv", records)
    print("Safety-sensitive counts:", [r["safety_sensitive"] for r in records])


def grouping_sensitivity():
    case = CASES["CVE-2022-22965"]
    assert case["gates"] == ("jdk9", "tomcat", "war") and not case["known"]
    grouped = case | {"gates": ("jdk9", "tomcat_and_war")}
    base_probability = 0.5
    # Preserve path prevalence by using the joint probability of both conditions.
    merged_probability = base_probability ** 2
    records = []
    for harm_cost in (1, 3):
        a = compare(case, "SO", base_probability, harm_cost=harm_cost)
        b = compare(grouped, "SO", base_probability, harm_cost=harm_cost,
                    gate_probabilities={"tomcat_and_war": merged_probability})
        assert a["scoped_no_path_weight"] == b["scoped_no_path_weight"] == (1 - base_probability ** 3) ** 2
        for name, row in (("separate", a), ("grouped_boolean_conjunction", b)):
            records.append({"question_design": name, "harm_cost": harm_cost,
                            "merged_probability": merged_probability if name.startswith("grouped") else "",
                            **{key: row[key] for key in (
                                "scoped_no_path_weight", "sorted_serial_mean_fields", "sorted_serial_mean_rounds",
                                "sorted_serial_mean_cost", "parallel_mean_fields", "parallel_mean_rounds",
                                "parallel_mean_cost", "full_mean_cost",
                            )}})
    write_rows(ROOT / "question_grouping_sensitivity.csv", records)
    for r in records:
        print(r)


if __name__ == "__main__":
    exploitation_sensitivity()
    grouping_sensitivity()
