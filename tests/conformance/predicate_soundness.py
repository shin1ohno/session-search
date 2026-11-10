#!/usr/bin/env python3
"""N16: equivalence predicates must reject every empirically detected mutant."""
import json
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sr_path, binary, artifact_dir = sys.argv[1:4]
source = open(os.path.join(HERE, "classify_survivors.py"), encoding="utf-8").read()
head = source.split("# Constructed inputs aimed at breaking each predicate")[0]
sys.argv = ["classify", sr_path, binary, artifact_dir]
exec(compile(head, "classify-head", "exec"))
gates = json.load(open(os.path.join(artifact_dir, "gate-mutants.json")))
results = gates["results"]
killed = [r["mutant"] for r in results if r["gate"] in ("structure", "baseline")]
runtime_count = len(killed)
killed += [r["mutant"] for r in gates["generator_rejections"]]
wrong = [m for m in killed if classify(m) != "unresolved"]
out = {"killed_mutants_checked": len(killed), "runtime_detected_checked": runtime_count, "generator_rejections_checked": len(gates["generator_rejections"]), "killed_mutants_the_predicates_call_equivalent": len(wrong), "wrong": wrong}
with open(os.path.join(artifact_dir,"predicate-soundness.json"),"w") as f: json.dump(out,f,indent=2)
print(json.dumps(out))
assert killed and not wrong
