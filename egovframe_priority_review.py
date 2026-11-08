"""Compare evidence-request policies under alternative response weights and costs."""

import csv
import json
import sys
from functools import lru_cache
from itertools import product
from pathlib import Path

from egovframe_priority_reproduce import CASES, TABLE, supplier_result, analyse


EVIDENCE = json.loads(Path(__file__).with_name("public_ssvc_evidence.json").read_text(encoding="utf-8"))
RECORDS = {item["id"]: item["values"] for item in EVIDENCE["records"]}


def public_pairs(cve):
    if not RECORDS[cve]:
        # The researcher-coded PoC fixes exploitation only; retain all six
        # utility and technical-impact combinations for that category.
        return sorted(set(TABLE[EVIDENCE["supplier_assessment"][cve]["exploitation"]]))
    entry, = RECORDS[cve]
    inputs = {key: value for item in entry["options"] for key, value in item.items()}
    assert inputs["Automatable"] == "yes"
    offset = int(inputs["Technical Impact"] == "total")
    group = TABLE[inputs["Exploitation"]]
    return sorted({group[2 + offset], group[4 + offset]})


def compare(case, pair, p, harm_probability=0.5, harm_cost=1, *, gate_probabilities=None):
    known = case["known"]
    gates = case["gates"]
    fields = [f"{site}.{field}" for site in ("A", "B")
              for field in (*gates, "safety_evidence") if f"{site}.{field}" not in known]
    # Visit the institution with fewer unresolved attack conditions first; ties follow A, B.
    sites = sorted(("A", "B"), key=lambda site: sum(f"{site}.{gate}" in fields for gate in gates))
    order = [f"{site}.{field}" for site in sites for field in (*gates, "safety_evidence")
             if f"{site}.{field}" in fields]
    assignments = list(product((False, True), repeat=len(fields)))
    states = [known | dict(zip(fields, bits)) for bits in assignments]
    outcomes = [supplier_result(case, state, pair) for state in states]
    universe = (1 << len(states)) - 1
    ones = {key: sum(1 << i for i, state in enumerate(states) if state[key]) for key in fields}
    masks = [sum(1 << i for i, label in enumerate(outcomes) if label == value) for value in set(outcomes)]

    def done(mask):
        return sum(bool(mask & group) for group in masks) == 1

    def ask(mask, keys, state):
        for key in keys:
            mask &= ones[key] if state[key] else universe ^ ones[key]
        return mask

    def cost(keys):
        return sum(harm_cost if key.endswith(".safety_evidence") else 1 for key in keys)

    # Assign independent Bernoulli weights to unobserved responses.
    gate_probabilities = gate_probabilities or {}
    weights = []
    for bits in assignments:
        weight = 1.0
        for key, bit in zip(fields, bits):
            field = key.split(".", 1)[1]
            probability = harm_probability if field == "safety_evidence" else gate_probabilities.get(field, p)
            weight *= probability if bit else 1 - probability
        weights.append(weight)
    observations = {"full": [], "sorted_serial": [], "site_batch": [], "parallel": []}
    for i, (weight, state) in enumerate(zip(weights, states)):
        observations["full"].append((weight, len(fields), 1, cost(fields)))

        replies = dict(known)
        requested = []
        mask = universe
        for key in order:
            if done(mask):
                break
            site, field = key.split(".")
            if any(replies.get(f"{site}.{gate}") is False for gate in gates):
                continue
            if field == "safety_evidence" and pair[0] == pair[1]:
                continue
            mask = ask(mask, (key,), state)
            requested.append(key)
            replies[key] = state[key]
        assert mask & (1 << i) and done(mask)
        observations["sorted_serial"].append((weight, len(requested), len(requested), cost(requested)))

        requested = []
        rounds = 0
        mask = universe
        for site in sites:
            batch = [f"{site}.{gate}" for gate in gates if f"{site}.{gate}" in fields]
            if batch:
                mask = ask(mask, batch, state)
                requested.extend(batch)
                rounds += 1
            if done(mask):
                break
            key = f"{site}.safety_evidence"
            if key in fields and all(state[f"{site}.{gate}"] for gate in gates) and pair[0] != pair[1]:
                mask = ask(mask, (key,), state)
                requested.append(key)
                rounds += 1
            if done(mask):
                break
        assert mask & (1 << i) and done(mask)
        observations["site_batch"].append((weight, len(requested), rounds, cost(requested)))

        batch_one = [key for key in fields if not key.endswith(".safety_evidence")]
        mask = ask(universe, batch_one, state)
        batch_two = []
        if not done(mask):
            batch_two = [f"{site}.safety_evidence" for site in ("A", "B")
                         if f"{site}.safety_evidence" in fields
                         and all(state[f"{site}.{gate}"] for gate in gates)]
            mask = ask(mask, batch_two, state)
        assert mask & (1 << i) and done(mask)
        requested = batch_one + batch_two
        observations["parallel"].append((weight, len(requested), bool(batch_one) + bool(batch_two), cost(requested)))

    output = {}
    for policy, data in observations.items():
        assert abs(sum(x[0] for x in data) - 1) < 1e-10
        for i, metric in enumerate(("fields", "rounds", "cost"), start=1):
            output[f"{policy}_mean_{metric}"] = sum(x[0] * x[i] for x in data)
            output[f"{policy}_max_{metric}"] = max(x[i] for x in data)
    output["scoped_no_path_weight"] = sum(w for w, label in zip(weights, outcomes) if label == "R")

    @lru_cache(maxsize=None)
    def mass(mask):
        if not mask:
            return 0.0
        # Sum the probability weights of the states still consistent with the replies.
        total = 0.0
        while mask:
            bit = mask & -mask
            total += weights[bit.bit_length() - 1]
            mask ^= bit
        return total

    # Weight each request cost by the probability of reaching that state set.
    # With the prerequisite enabled, ask about harm only after confirming the path.
    @lru_cache(maxsize=None)
    def optimal_weighted_cost(mask, require_path):
        if done(mask):
            return 0.0
        choices = []
        for field in fields:
            if require_path and field.endswith(".safety_evidence"):
                site = field.split(".", 1)[0]
                required = (f"{site}.{gate}" for gate in gates)
                if any(not (known[key] if key in known else (mask & ones[key]) == mask)
                       for key in required):
                    continue
            yes = mask & ones[field]
            no = mask ^ yes
            if yes and no:
                choices.append(mass(mask) * cost((field,)) +
                               optimal_weighted_cost(yes, require_path) +
                               optimal_weighted_cost(no, require_path))
        return min(choices)

    output["optimal_expected_cost"] = optimal_weighted_cost(universe, False)
    output["serial_expected_cost_gap"] = max(0.0, output["sorted_serial_mean_cost"] -
                                            output["optimal_expected_cost"])
    output["prerequisite_optimal_cost"] = optimal_weighted_cost(universe, True)
    output["serial_prerequisite_gap"] = output["sorted_serial_mean_cost"] - output["prerequisite_optimal_cost"]
    assert output["optimal_expected_cost"] <= output["prerequisite_optimal_cost"] + 1e-10
    assert output["prerequisite_optimal_cost"] <= output["sorted_serial_mean_cost"] + 1e-10
    optimal_weighted_cost.cache_clear()
    mass.cache_clear()
    return output


def homogeneous(k, n, p, s, sensitive):
    """Return expected serial requests for n identical, independent institutions."""
    per_site = sum(p**i for i in range(k)) + (p**k if sensitive else 0)
    stop = p**k * (s if sensitive else 1)
    return per_site * sum((1-stop)**i for i in range(n))


def provisional_product(pairs, path_plausible, coverage_supported, safety):
    """Return provisional urgency given path plausibility and evidence coverage."""
    if not path_plausible:
        return "R"
    assume_significant = safety != "minimal" or not coverage_supported
    return max((pair[assume_significant] for pair in pairs), key="DSOI".index)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    rows = []
    for cve, case in CASES.items():
        for sensitive, p, harm_p, harm_cost in product((False, True), (0.2, 0.5, 0.8), (0.25, 0.5, 0.75), (1, 3)):
            pair = "SO" if sensitive else "OO"
            rows.append({
                "cve": cve, "psi_sensitive": int(sensitive), "gate_p": p,
                "safety_p": harm_p, "safety_cost": harm_cost, **compare(case, pair, p, harm_p, harm_cost),
            })
    destination = Path(__file__).with_name("egovframe_priority_sensitivity.csv")
    with destination.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print("Uniform comparison:")
    for cve, case in CASES.items():
        for pair in ("OO", "SO"):
            r = compare(case, pair, 0.5)
            original = analyse(case, pair)
            assert abs(r["sorted_serial_mean_fields"] - original["adaptive_mean"]) < 1e-10
            print(cve, pair, [round(r[k], 6) for k in (
                "full_mean_fields", "parallel_mean_fields", "parallel_mean_rounds",
                "sorted_serial_mean_fields", "sorted_serial_max_fields",
                "site_batch_mean_fields", "site_batch_mean_rounds", "scoped_no_path_weight")])
    verified_profiles = 0
    for case in CASES.values():
        for pair in (pair for group in TABLE.values() for pair in group):
            simple = compare(case, pair, 0.5)
            exact = analyse(case, pair)
            assert abs(simple["sorted_serial_mean_fields"] - exact["adaptive_mean"]) < 1e-10
            assert simple["sorted_serial_max_fields"] == exact["adaptive_worst"] == exact["fixed_fields"]
            verified_profiles += 1
    assert verified_profiles == 54
    print("Simple and exact policies agree on the mean and worst count in", verified_profiles, "profiles.")
    print("Public-input pairs (minimal then significant):")
    expected_provisional = {"CVE-2022-22965": "I", "CVE-2022-22980": "I", "CVE-2024-38816": "O"}
    for cve in CASES:
        pairs = public_pairs(cve)
        provisional = provisional_product(pairs, True, False, "unknown")
        assert provisional == expected_provisional[cve]
        print(cve, pairs, "provisional:", provisional)
    traversal = CASES["CVE-2024-38816"]
    path_traversal = public_pairs("CVE-2024-38816")[0]
    # Check that missing safety evidence at B leaves two outcomes when B's path
    # holds and A's path is excluded.
    example = {f"{site}.{gate}": True for site in ("A", "B") for gate in traversal["gates"]}
    example.update({"A.filesystem": False, "A.safety_evidence": False})
    candidates = [supplier_result(traversal, example | {"B.safety_evidence": bit}, path_traversal)
                  for bit in (False, True)]
    assert candidates == ["S", "O"]
    assert provisional_product([path_traversal], True, False, "unknown") == "O"
    assert provisional_product([path_traversal], True, False, "minimal") == "O"
    assert provisional_product([path_traversal], True, True, "minimal") == "S"
    assert provisional_product([path_traversal], True, False, "significant") == "O"
    assert provisional_product([path_traversal], False, False, "unknown") == "R"
    print("Scoped missing safety example:", candidates, "provisional: O")
    print("Product coverage gates verified.")
    first = next(iter(CASES.values()))
    print("Sensitivity for (3,3), differing safety outcomes:")
    for p in (0.2, 0.5, 0.8):
        r = compare(first, "SO", p, harm_cost=3)
        assert abs(homogeneous(3, 2, p, 0.5, True) - r["sorted_serial_mean_fields"]) < 1e-10
        print(p, [round(r[k], 6) for k in (
            "full_mean_cost", "parallel_mean_fields", "parallel_mean_rounds",
            "parallel_mean_cost", "sorted_serial_mean_fields", "sorted_serial_mean_cost")])
    print("No hypothetical pre-replies:")
    for cve, case in CASES.items():
        r = compare(case | {"known": {}}, "SO", 0.5)
        print(cve, [round(r[k], 6) for k in (
            "full_mean_fields", "parallel_mean_fields", "sorted_serial_mean_fields")])
    print("Scale example:", [(n, round(homogeneous(3,n,0.5,0.5,True), 6)) for n in (2, 5, 10)])
    for cost_factor in (1, 3):
        worst = max((r for r in rows if r["safety_cost"] == cost_factor),
                    key=lambda r: r["serial_expected_cost_gap"])
        print("Weighted comparison maximum gap:", {k: worst[k] for k in (
            "cve", "gate_p", "safety_p", "safety_cost", "sorted_serial_mean_cost",
            "optimal_expected_cost", "serial_expected_cost_gap")})
    maximum_gap = max(abs(r["serial_prerequisite_gap"]) for r in rows)
    assert maximum_gap < 1e-12
    print("Prerequisite-constrained comparison:", len(rows), "profiles; maximum absolute gap:", maximum_gap)
    print("Sensitivity rows:", len(rows))


if __name__ == "__main__":
    main()
