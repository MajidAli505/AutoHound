#!/usr/bin/env python3
"""AutoHound automated tests - run: python3 test_autohound.py
Uses the fake CORP.LOCAL sample data. Every check is an assert on a KNOWN
ground-truth fact of that sample, so a regression in the parser, the graph,
the BFS, the scoring or the verifier fails loudly here."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from autohound import build_graph, analyze, render_path

g = build_graph(["sample_data/sample_all.json"])
f = analyze(g)
passed = []
def check(name, cond):
    assert cond, f"FAILED: {name}"
    passed.append(name)

# Graph sanity
check("sample graph has 14 nodes", f["stats"]["nodes"] == 14)
check("sample graph has >=17 edges", f["stats"]["edges"] >= 17)

# Known ground-truth path: ALICE -> HELPDESK -> WS01 -> JOHN_ADMIN (3 hops)
alice = [p for p in f["paths"] if p["start"].startswith("ALICE@")]
check("ALICE has a Tier-Zero path", len(alice) == 1)
check("ALICE path is 3 hops", alice[0]["length"] == 3)
check("ALICE path goes via HELPDESK and WS01",
      "HELPDESK" in render_path(g, alice[0]["path"]) and "WS01" in render_path(g, alice[0]["path"]))
check("ALICE path confidence is high (MemberOf+AdminTo+HasSession = 66.5%)",
      alice[0]["confidence"] == 66.5)

# DCSync: BACKUP_OPS (via GetChangesAll) - and it is NOT high-value itself
check("DCSync found", len(f["dcsync"]) >= 1)
check("BACKUP_OPS is a DCSync principal", any("BACKUP_OPS" in d["source"] for d in f["dcsync"]))

# Roastable accounts
check("SVC_SQL is kerberoastable", [k["name"] for k in f["kerberoastable"]] == ["SVC_SQL@CORP.LOCAL"])
check("DAVE is AS-REP roastable", [a["name"] for a in f["asrep"]] == ["DAVE@CORP.LOCAL"])

# Unconstrained delegation: SRV01 yes, and no DC in the sample so nothing else
check("SRV01 flagged for unconstrained delegation",
      [u["name"] for u in f["unconstrained"]] == ["SRV01.CORP.LOCAL"])

# Self-verification must be 100% on the sample
check("all sample Tier-Zero paths verify", f["verification"]["tier_zero_paths"].startswith(
      f"{len(f['paths'])}/{len(f['paths'])}"))
check("all sample admin chains verify", f["verification"]["admin_chains"].startswith(
      f"{len(f['admin_chains'])}/{len(f['admin_chains'])}"))

# Every reported path's edges must really exist (independent re-walk)
for p in f["paths"] + f["admin_chains"]:
    for a, et, b in p["path"]:
        assert (a, b, et) in g.edges_set, f"phantom edge in path: {a} {et} {b}"
passed.append("no phantom edges in any reported path")

# Alternative-path counting runs and is sane
check("alt path counts present", all("alt_paths" in p for p in f["paths"]))

# Data-quality block exists and DC detection does not crash on the sample (no DC computer there)
check("data_quality present", "node_types" in f["data_quality"])
check("remediation generated", isinstance(f["remediation"], list))

print(f"ALL {len(passed)} TESTS PASSED")
for t in passed:
    print("  PASS:", t)
