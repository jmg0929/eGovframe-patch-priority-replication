"""Enumerate survey outcomes for two modeled institutions and three CVEs."""

import csv
import sys
from functools import lru_cache
from itertools import product
from pathlib import Path
from statistics import mean


# CERT/CC supplier decision table v1.0.0. Rows within each exploitation
# category are ordered by utility, then technical impact. Each pair gives the
# response for minimal and significant safety impact, respectively.
# D = defer, S = scheduled, O = out-of-cycle, I = immediate.
TABLE = {
    "none": ("DS", "SO", "SO", "SO", "SO", "OO"),
    "public poc": ("SO", "SI", "SI", "OI", "OI", "OI"),
    "active": ("OI", "OI", "OI", "OI", "II", "II"),
}
UTILITIES = ("laborious", "efficient", "super effective")
IMPACTS = ("partial", "total")
REVIEW = "R"  # The surveyed institutions do not meet the modeled attack conditions.
CASES = {
    "CVE-2022-22965": {
        "release": "4.0.0", "library": "spring-webmvc", "version": "5.3.6",
        "gates": ("jdk9", "tomcat", "war"),
        "known": {},
    },
    "CVE-2022-22980": {
        "release": "4.1.0", "library": "spring-data-mongodb", "version": "3.4.0",
        "gates": ("query_form", "unsanitized_input", "unrestricted_context"),
        "known": {"B.query_form": True},
    },
    "CVE-2024-38816": {
        "release": "4.3.0", "library": "spring-webmvc", "version": "5.3.37",
        "gates": ("router_static", "filesystem", "no_http_firewall", "other_server"),
        "known": {"A.router_static": True, "A.other_server": True, "B.router_static": True},
    },
}


def instances(case, responses):
    return {
        site: all(responses[f"{site}.{gate}"] for gate in case["gates"])
        for site in ("A", "B")
    }


def supplier_result(case, responses, pair):
    matches = instances(case, responses)
    if not any(matches.values()):
        return REVIEW
    significant = any(matches[site] and responses[f"{site}.safety_evidence"] for site in matches)
    return pair[significant]


def analyse(case, pair):
    fields = [
        f"{site}.{field}"
        for site in ("A", "B")
        for field in (*case["gates"], "safety_evidence")
    ]
    known = case["known"]
    unknown = [field for field in fields if field not in known]
    assignments = list(product((False, True), repeat=len(unknown)))
    states = [known | dict(zip(unknown, bits)) for bits in assignments]
    outcomes = [supplier_result(case, state, pair) for state in states]
    universe = (1 << len(states)) - 1
    one_masks = [
        sum(1 << index for index, bits in enumerate(assignments) if bits[col])
        for col in range(len(unknown))
    ]
    outcome_masks = {
        label: sum(1 << i for i, outcome in enumerate(outcomes) if outcome == label)
        for label in sorted(set(outcomes))
    }
    outcome_by_bits = dict(zip(assignments, outcomes))

    # Minimize worst-case questions, then the total across equally weighted states.
    @lru_cache(maxsize=None)
    def plan(mask):
        if sum(bool(mask & candidates) for candidates in outcome_masks.values()) == 1:
            return 0, 0, None
        options = []
        for col, ones in enumerate(one_masks):
            yes = mask & ones
            no = mask ^ yes
            if yes and no:
                y_worst, y_total, _ = plan(yes)
                n_worst, n_total, _ = plan(no)
                options.append((1 + max(y_worst, n_worst), mask.bit_count() + y_total + n_total, col))
        return min(options)

    def gate_first(state):
        matches = []
        count = 0
        for site in ("A", "B"):
            for gate in case["gates"]:
                field = f"{site}.{gate}"
                count += field in unknown
                if not state[field]:
                    break
            else:
                matches.append(site)
        if not matches:
            return REVIEW, count
        if pair[0] == pair[1]:
            return pair[0], count
        for site in matches:
            count += 1
            if state[f"{site}.safety_evidence"]:
                return pair[1], count
        return pair[0], count

    # Include a field in the fixed request if flipping it alone can change the outcome.
    fixed = []
    for col, field in enumerate(unknown):
        if any(
            outcome_by_bits[bits] != outcome_by_bits[bits[:col] + (not bits[col],) + bits[col + 1:]]
            for bits in assignments
        ):
            fixed.append(field)
    observed = {}
    for state, outcome in zip(states, outcomes):
        key = tuple(state[field] for field in fixed)
        assert observed.setdefault(key, outcome) == outcome

    gate_counts = []
    adaptive_counts = []
    for index, (state, expected) in enumerate(zip(states, outcomes)):
        result, count = gate_first(state)
        assert result == expected
        gate_counts.append(count)
        mask = universe
        count = 0
        while (col := plan(mask)[2]) is not None:
            yes = mask & one_masks[col]
            mask = yes if state[unknown[col]] else mask ^ yes
            count += 1
        assert mask & (1 << index)
        assert mask & outcome_masks[expected] == mask
        adaptive_counts.append(count)
    worst, total, first = plan(universe)
    assert worst == max(adaptive_counts) and total == sum(adaptive_counts)

    # Count complete states whose outcome remains ambiguous when only B's
    # safety evidence is missing.
    b_safety = unknown.index("B.safety_evidence")
    unresolved = sum(
        expected != outcome_by_bits[bits[:b_safety] + (not bits[b_safety],) + bits[b_safety + 1:]]
        for bits, expected in zip(assignments, outcomes)
    )
    plan.cache_clear()
    return {
        "states": len(states),
        "initial_outcomes": "/".join(sorted(set(outcomes))),
        "all_fields": len(unknown),
        "fixed_fields": len(fixed),
        "gate_first_mean": mean(gate_counts),
        "gate_first_worst": max(gate_counts),
        "adaptive_mean": mean(adaptive_counts),
        "adaptive_worst": worst,
        "first_question": unknown[first] if first is not None else "",
        "unresolved_if_b_safety_unavailable": unresolved,
    }


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    rows = []
    for cve, case in CASES.items():
        for exploitation, utility, impact in product(TABLE, UTILITIES, IMPACTS):
            pair = TABLE[exploitation][2 * UTILITIES.index(utility) + IMPACTS.index(impact)]
            rows.append({
                "cve": cve,
                "exploitation": exploitation,
                "utility": utility,
                "technical_impact": impact,
                "supplier_pair": pair,
                **analyse(case, pair),
            })
    assert len(rows) == 54
    destination = Path(__file__).with_name("egovframe_priority_results.csv")
    with destination.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"54 experiments, {sum(row['states'] for row in rows)} scenario-profile states.")
    for cve in CASES:
        subset = [r for r in rows if r["cve"] == cve]
        print(cve, " / ".join(
            f"{key}={min(r[key] for r in subset):.4f}–{max(r[key] for r in subset):.4f}"
            for key in ("all_fields", "fixed_fields", "gate_first_mean", "adaptive_mean",
                        "gate_first_worst", "adaptive_worst", "unresolved_if_b_safety_unavailable")
        ))
    for row in rows:
        if (row["exploitation"], row["utility"], row["technical_impact"]) == ("none", "efficient", "partial"):
            print("Example", row)


if __name__ == "__main__":
    main()
