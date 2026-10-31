#!/usr/bin/env python3
"""Interpret a full/smoke artifact run without recomputing or modifying measurements."""
import argparse
import csv
import hashlib
import json
import os
import re
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source, out = args.input.resolve(), args.output.resolve()
    provenance = json.loads((source / "reproduce-provenance.json").read_text())
    if not provenance["success"] or provenance["mode"] != "reproduce":
        raise ValueError("evaluation needs a successful reproduction, not a partial run")
    if provenance.get("implementationProfile") != "public-guards-v1":
        raise ValueError("this renderer requires public-guards-v1 measurements; older reduced evidence remains historical")
    for name, expected in provenance["sha256"].items():
        if digest(source / name) != expected:
            raise ValueError(f"measurement hash mismatch: {name}")

    def rows(name):
        with (source / name).open(newline="") as stream:
            return list(csv.DictReader(stream))

    proof = rows("scalability.csv")
    gas = rows("gas.csv")
    classification = rows("classification.csv")
    correctness = rows("correctness.csv")
    robustness = rows("robustness.csv")
    if any(row["passed"] != "true" for row in correctness):
        raise ValueError("correctness evidence contains a failure")
    if any(row["status"] != "Success" for row in robustness):
        raise ValueError("robustness evidence contains a failure")
    if any(int(row["violations"]) != 0 for row in classification):
        raise ValueError("classification evidence contains a violation")
    out.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                         "svg.hashsalt": "vc-rollup-evaluation", "svg.fonttype": "none", "axes.spines.top": False,
                         "axes.spines.right": False})

    def save(fig, name):
        fig.savefig(out / f"{name}.svg", bbox_inches="tight", metadata={"Date": None})
        svg = out / f"{name}.svg"
        svg.write_text("\n".join(line.rstrip() for line in svg.read_text().splitlines()) + "\n")
        fig.savefig(out / f"{name}.png", bbox_inches="tight", dpi=180)
        plt.close(fig)

    def grouped(pattern):
        result = defaultdict(list)
        for row in proof:
            match = re.fullmatch(pattern, row["case"])
            if match:
                result[int(match.group(1))].append(row)
        if not result:
            raise ValueError(f"missing benchmark cases: {pattern}")
        return dict(sorted(result.items()))

    thresholds = grouped(r"at least (\d+) active")
    groups = grouped(r"hidden member of S, \|S\| = (\d+)")
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.7), layout="constrained")
    for ax, data, xlabel in zip(axes, [thresholds, groups], ["Required active credentials k", "Anchored group size"]):
        for column, label, color, marker in [("prove_ms", "Generate", "#176b92", "o"),
                                               ("verify_ms", "Verify", "#a64b1a", "s")]:
            samples = [[float(r[column]) for r in cases] for cases in data.values()]
            means = [statistics.mean(s) for s in samples]
            errors = [[m - min(s) for m, s in zip(means, samples)],
                      [max(s) - m for m, s in zip(means, samples)]]
            ax.errorbar(list(data), means, yerr=errors, capsize=4, label=label, color=color, marker=marker)
        ax.set(xlabel=xlabel, ylabel="Wall-clock time (ms)", xticks=list(data))
        ax.set_ylim(bottom=0)
        ax.grid(axis="y", alpha=.2)
        ax.legend(frameon=False)
    fig.suptitle("Proof cost: mean and observed range of three paired samples")
    save(fig, "proof-cost")

    group_gas = [(int(re.search(r"\|S\| = (\d+)", r["detail"])[1]), int(r["gas"]), int(r["calldata_bytes"]))
                 for r in gas if r["operation"] == "createGroup"]
    group_gas.sort()
    fig, ax = plt.subplots(figsize=(6, 3.4), layout="constrained")
    ax.bar([str(n) for n, _, _ in group_gas], [g / 1000 for _, g, _ in group_gas], color="#176b92")
    ax.set(xlabel="Group size", ylabel="Gas (thousands)", title="Group creation: one transaction per size")
    ax.grid(axis="y", alpha=.2)
    save(fig, "group-gas")

    volatile = [r for r in classification if r["class"] == "volatile"]
    fig, ax = plt.subplots(figsize=(7, 3.2), layout="constrained")
    labels = ["Issued-only domains" if r["model"].startswith("system") else "Arbitrary-ID domains" for r in volatile]
    conservative = [int(r["conservative_classifications"]) for r in volatile]
    necessary = [int(r["formulas"]) - c for r, c in zip(volatile, conservative)]
    ax.barh(labels, conservative, label="Semantically stable or co-stable in bounded states", color="#176b92")
    ax.barh(labels, necessary, left=conservative, label="Neither in bounded states", color="#a64b1a")
    ax.set(xlabel="Sampled formulas classified volatile", title="Conservatism of the syntactic classification")
    ax.legend(loc="upper center", bbox_to_anchor=(.5, -.23), frameon=False, fontsize=8)
    save(fig, "classification")

    def summary(data):
        lines = []
        for n, samples in data.items():
            times = []
            for column in ["prove_ms", "verify_ms"]:
                values = [float(r[column]) for r in samples]
                times.append(f"{statistics.mean(values):.1f} ({min(values):.1f}–{max(values):.1f})")
            sizes = [int(r["proof_element_bytes"]) for r in samples]
            size = str(sizes[0]) if len(set(sizes)) == 1 else f"{min(sizes)}–{max(sizes)}"
            lines.append(f"| {n} | {' | '.join(times)} | {size} |")
        return "\n".join(lines)

    relatives = os.path.relpath(source, out)
    revision = provenance["revision"]
    cpu = provenance["platform"]["cpu"]
    memory = provenance["platform"]["totalMemoryBytes"] / 1024 ** 3
    mode = "SMOKE: reduced workload, unsuitable for full scaling conclusions" if provenance["smoke"] else "Full workload"
    formula_count = sum(int(r["formulas"]) for r in classification)
    ctext = "\n".join(f"- {r['model']}: {r['conservative_classifications']}/{r['formulas']} volatile verdicts "
                       f"({100 * int(r['conservative_classifications']) / int(r['formulas']):.1f}%) are semantically stable or co-stable over the enumerated states."
                       for r in volatile)
    gas_table = "\n".join(f"| {n} | {g:,} | {b:,} |" for n, g, b in group_gas)
    actions = [r for r in gas if r["operation"] in ["revoke", "guardedRevoke", "guardedIssueUpdate"]]
    action_table = "\n".join(f"| {r['operation']} | {r['detail']} | {int(r['gas']):,} | {int(r['calldata_bytes']):,} |" for r in actions)
    controls = [r for r in actions if r["detail"].startswith("control:")]
    if len(controls) != 3:
        raise ValueError("expected three controlled update paths")
    bare = next(int(r["gas"]) for r in controls if r["operation"] == "revoke")
    overhead_table = "\n".join(f"| {r['detail'].removeprefix('control: ')} | {int(r['gas']):,} | {int(r['gas']) - bare:+,} |" for r in controls)
    fig, ax = plt.subplots(figsize=(7, 3.4), layout="constrained")
    ax.bar(["Bare update", "Public group guard", "Public registry guard"],
           [int(r["gas"]) / 1000 for r in controls], color=["#777777", "#176b92", "#a64b1a"])
    ax.set(ylabel="Gas (thousands)", title="Update paths from an identical snapshotted state")
    ax.grid(axis="y", alpha=.2)
    save(fig, "guard-overhead")
    scaling_answer = ("**Smoke data are a pipeline check, not a scaling evaluation.** Use a full run for the conclusions and dimensions below." if provenance["smoke"] else "**Both tested dimensions increase computation, while they affect proof size differently.** Requiring more active credentials adds credential and distinctness evidence. Hidden membership in a larger anchored group keeps the measured encoded proof size fixed while increasing the measured work.")
    text = f"""# Evaluation of ledger-enforced public credential guards

{mode}. This evaluation answers four questions about the implemented public-guard subset. It combines functional scenarios, bounded semantic checks and measured proof/EVM costs under the documented trust assumptions.

## Method and provenance

Measurements come from [source revision {revision[:7]}](https://github.com/csillag2004/vc-rollup/commit/{revision}), run on {provenance['startedAt']}. The source worktree was {'modified' if provenance['dirty'] else 'clean'}. The machine was {cpu}, {provenance['platform']['logicalCpus']} logical CPUs, {memory:.1f} GiB RAM, Linux. Proof computations use one Node.js process; this was a shared host with no CPU isolation. Node {provenance['tools']['node']}, Foundry 1.8.6, solc 0.8.30 and the Prague hardfork were used. [Provenance and raw-output hashes]({relatives}/reproduce-provenance.json) specify the exact environment.

Each proof case has one warm-up and three paired generation/verification samples. Tables report mean and observed minimum–maximum, not confidence intervals. Cryptographic keys, IDs and blinding are fresh OS randomness. Formula sampling uses seed 2026, depth at most four, and a universe of four IDs. Every comparable state pair is enumerated for each sampled formula; the formula space itself is not exhaustively enumerated.

## RQ1: Does ledger evaluation prevent the demonstrated false-guard update?

**Yes for the tested public reservation policy and interleaving.** Alice and Bob obtain valid guards at the same state. The naive updater checks both and later revokes both credentials, yielding two reservations. With the policy bound to the action, Alice's update succeeds and Bob's update reverts with `GuardFalse`. Bob's old presentation remains cryptographically valid but is no longer fresh. The reservation's stable "flat is taken" proof remains valid after later issuance. A separate fixture verifies a stable proof after actual later issuance and revocation in that proof's registry. A separate holder proof verifies signature, group membership and revoked status without naming the group member in the proof interface.

The result is a controlled sequential interleaving of a check/use race, not a throughput or many-client concurrency experiment. It does not establish end-to-end anonymity. The contract evaluates the registered public program at execution. A bound update policy cannot be removed or replaced. Unsupported private presented guards are rejected on binding and execution, rather than accepted on the strength of a hash or retrospective proof check. The event proof is available for independent audit, but public guard truth is determined by ledger counters. Policy authors choose the initial program; enforcement does not establish that it represents an external agreement or the descriptive query string.

The [correctness cases]({relatives}/correctness.csv), [BDD outcomes]({relatives}/bdd.json) and [reservation trace]({relatives}/reservation.json) record the observations. Robustness evidence covers duplicate issuance, unissued revocation despite a forged quotient witness, invalid group membership, false public guards, policy replacement/removal, unsupported private guards, malformed policy programs and proof-event integrity through the contract, actor and unit suites. [Robustness results]({relatives}/robustness.csv) and [actor integration output]({relatives}/guard-integration.tap) retain the run evidence. This is functional rejection coverage, not a denial-of-service assessment.

## RQ2: Is the classifier sound on the bounded sample, and how conservative is it?

**No classification violations were observed in {formula_count:,} sampled formulas across the two models.** A stable verdict must never turn false along the enumerated state order; a co-stable verdict must never turn true; a state-independent verdict must not change.

{ctext}

![Conservative volatile classifications](classification.svg)

These conservative verdicts can request stronger off-chain presentation freshness checking than the bounded semantics require. Public update guards are evaluated directly and do not depend on this classifier to establish guard truth. They are not false soundness claims: the syntactic rule deliberately over-approximates volatility. The percentages describe this generator and finite state space, not a representative production workload or a measured transaction-rejection rate. [Raw classification counts]({relatives}/classification.csv).

The separate Lean model provides ideal set-level proofs. The implementation now supplies structural lifecycle checks and actual public guard evaluation. The model is still not a refinement proof of Solidity or the compiler, and no end-to-end cryptographic or privacy proof is inferred from its theorems.

## RQ3: How do proof costs change with the threshold and anchored group size?

{scaling_answer}

![Proof generation and verification cost](proof-cost.svg)

Threshold cases:

| Active credentials k | Generate ms, mean (range) | Verify ms, mean (range) | Proof-element bytes |
|---:|---:|---:|---:|
{summary(thresholds)}

Hidden group-member cases:

| Group size | Generate ms, mean (range) | Verify ms, mean (range) | Proof-element bytes |
|---:|---:|---:|---:|
{summary(groups)}

"Proof-element bytes" counts compressed group elements and encoded scalars, excluding JSON framing, identifiers, transport headers and fetched registry history. A public query can therefore have zero proof-element bytes while still requiring data and computation. The full table also measures active/revoked credentials, an OR with a simulated branch, same-holder evidence and aggregate receipts. [All paired timing samples]({relatives}/scalability.csv).

Three samples on one shared host support a description of these runs, not a precise latency SLA or an asymptotic complexity claim. Setup, key generation, credential issuance and network history retrieval are outside the timed proof loops. The aggregate-receipt case receives an already computed witness; its generation time is not the cost of constructing that witness. The hidden-member fixtures keep one presented credential and two revocations, but registry history grows with the group, so this is an implementation scaling experiment rather than an isolated group-operation microbenchmark. Larger groups and thresholds beyond the tested range remain unmeasured.

## RQ4: What are the EVM execution and calldata costs?

**Group creation gets more expensive over the tested sizes.** It checks that each public member ID was issued and stores the fixed member list. Storage and per-member checks explain why this path is not constant-cost.

![Group-creation gas](group-gas.svg)

| Group size | Gas | Calldata bytes |
|---:|---:|---:|
{gas_table}

Group creation uses SRS degree 16 for every size shown. Each row above is one transaction, not a repeated-run estimate. The measurements also include registry/SRS setup, 16 issuances and the update variants below.

| Operation | Variant | Gas | Calldata bytes |
|---|---|---:|---:|
{action_table}

The three control rows restore the same Anvil snapshot before revoking the same ID with the same accumulator update. All policies exist before the snapshot. The action is deliberately unbound so that the bare path can execute. This compares total optional public-guard call cost, including policy lookup, public evaluation, proof bytes and events; it does not isolate a single EVM opcode or establish a universal overhead. The permanently bound rows are separate functional measurements.

![Controlled public-guard cost](guard-overhead.svg)

| Control path | Gas | Difference from bare update |
|---|---:|---:|
{overhead_table}

Each control path is measured once. Proof payloads differ between public group and whole-registry queries, and these payload differences are part of the measured call cost. These are public evaluation paths, not the older reduced design's CAS modes.

Calldata bytes include the selector and arguments. These are local Prague gas measurements, not OP Sepolia L1 data fees, currency costs, finality latency or throughput. [Per-transaction gas and calldata]({relatives}/gas.csv).

## Reproduction and scope

`just reproduce` runs the measurements on a fresh local chain and derives this evaluation under `out/evaluation/`. `just figures results/local out/evaluation` derives the text and figures from the committed full run without rerunning the measurements. The renderer verifies every recorded output hash before interpreting the CSVs. Smoke output is marked as reduced and must not replace the full-workload evaluation.

The evidence supports structural lifecycle checks, ledger-enforced public guards under a permanently bound policy, bounded classification checks and the measured proof/EVM costs. Private guard enforcement is not implemented: those update policies fail closed. Off-chain private status proofs retain their trapdoor-holder limitation. The evidence does not establish general classifier soundness from sampling alone, production throughput, full anonymity, or current public-testnet performance. The broader paper evaluation chapter and new live deployment are outside this companion-repository task.
"""
    (out / "evaluation.md").write_text(text)
    derived = {"measurementRevision": revision, "smoke": provenance["smoke"],
               "inputProvenanceSha256": digest(source / "reproduce-provenance.json"),
               "rendererSha256": digest(Path(__file__)), "matplotlib": matplotlib.__version__,
               "outputs": {p.name: digest(p) for p in sorted(out.iterdir()) if p.suffix in [".md", ".svg", ".png"]}}
    (out / "derivation.json").write_text(json.dumps(derived, indent=2) + "\n")
    print(f"Evaluation and figures written to {args.output}")


if __name__ == "__main__":
    main()
