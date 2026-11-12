#!/usr/bin/env python3
"""Require the proof regression gate to reject broken generator/classifier copies."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def main(artifacts):
    artifacts.mkdir(parents=True, exist_ok=True)
    generator = (ROOT / 'tools/gen_redact_tables.py').read_text()
    classifier = (HERE / 'classify_survivors.py').read_text()
    controls = [
        ('tail-bypass', '--generator', generator,
         '    width = 0\n', '    return 0\n    width = 0\n',
         'test_generator_cli_refuses_audit_rules'),
        ('tail-branch-bypass', '--generator', generator,
         '    widths = [check_tail(a, icase) for a in alts]',
         '    return\n    widths = [check_tail(a, icase) for a in alts]',
         'test_generator_rejects_boundary_backtracking'),
        ('subsumed-lazy', '--classifier', classifier,
         'seq[i + 1][0] is not C.MAX_REPEAT', 'not is_repeat(seq[i + 1])',
         'test_subsumed_optional_witnesses'),
        ('subsumed-captures', '--classifier', classifier,
         'if has_group(G.TREES[name][0]):', 'if False:',
         'test_subsumed_optional_witnesses'),
        ('assertion-captures', '--classifier', classifier,
         'if op in (C.ASSERT, C.ASSERT_NOT) and has_group(av[1]):', 'if False:',
         'test_subsumed_optional_witnesses'),
        ('subsumed-sequence', '--classifier', classifier,
         '    if len(body) != 1 or body[0][0] not in CHAR:\n        return False\n'
         '    cls = set(G.node_chars(body[0][0], body[0][1], sic))',
         '    cls = all_chars(body, sic)',
         'test_subsumed_optional_witnesses'),
    ]
    results = []
    for name, flag, source, old, new, test in controls:
        assert source.count(old) == 1, (name, 'mutation site changed')
        copy = artifacts / (name + '.py')
        copy.write_text(source.replace(old, new))
        result = subprocess.run([sys.executable, HERE / 'test_gate_proofs.py', flag, copy],
                                capture_output=True, text=True)
        log = result.stdout + result.stderr
        (artifacts / (name + '.log')).write_text(log)
        assert result.returncode == 1 and 'FAIL: ' + test in log, (name, log[-2000:])
        assert 'ERROR:' not in log and 'AssertionError:' in log, (name, log[-2000:])
        results.append({'control': name, 'exit': result.returncode, 'rejected_by': test})
        print('PASS proof negative control:', name, flush=True)
    (artifacts / 'proof-controls.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    main(parser.parse_args().artifacts.resolve())
