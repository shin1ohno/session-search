#!/usr/bin/env python3
"""Regression witnesses for generator rejection and survivor equivalence proofs.

The optional source paths let the same checks exercise deliberately broken copies.
"""
import argparse
import ast
import contextlib
import importlib.util
import io
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PARSER = argparse.ArgumentParser(description=__doc__)
PARSER.add_argument('--generator', type=Path, default=ROOT / 'tools/gen_redact_tables.py')
PARSER.add_argument('--classifier', type=Path, default=Path(__file__).with_name('classify_survivors.py'))
ARGS = PARSER.parse_args()


def load_generator(directory):
    spec = importlib.util.spec_from_file_location('gate_generator', ARGS.generator)
    generator = importlib.util.module_from_spec(spec)
    argv = sys.argv
    try:
        sys.argv = [str(ARGS.generator), str(ROOT / 'vendor/memory-mcp/session_redact.py'),
                    str(directory / 'tables.rs')]
        with contextlib.redirect_stdout(io.StringIO()):
            spec.loader.exec_module(generator)
    finally:
        sys.argv = argv
    return generator


class GateProofs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.work.cleanup)
        cls.directory = Path(cls.work.name)
        cls.g = load_generator(cls.directory)
        # Execute the actual predicate definitions, without its CLI's mutation hunt.
        source = ast.parse(ARGS.classifier.read_text())
        definitions = ast.Module(body=[n for n in source.body if isinstance(n, ast.FunctionDef)],
                                 type_ignores=[])
        cls.predicates = {'G': cls.g, 'C': cls.g.C, 're': re,
                          'CHAR': (cls.g.C.LITERAL, cls.g.C.NOT_LITERAL, cls.g.C.IN, cls.g.C.ANY)}
        exec(compile(definitions, str(ARGS.classifier), 'exec'), cls.predicates)

    def compile_rule(self, pattern):
        return self.g.compile_tree('synthetic', self.g.plain(self.g.P.parse(pattern)), False)

    def test_generator_rejects_boundary_backtracking(self):
        cases = [
            (r'\bAKIA[A-Z0-9]{16,}?\b', 'lazy'),
            (r'\bAIza[0-9A-Za-z_-]{2,4}[a-z]\b', 'non-final'),
            (r'\bAKIA(?:-B|)\b', 'unequal'),
            (r'\bA(?:[a-z]+?)\b', 'lazy'),
            (r'\bA(?i:[a-z]+?)\b', 'lazy'),
            (r'\bA(?:[a-z]{1,3})[a-z]+\b', 'non-final'),
            (r'\bA(?:(?:-B|))\b', 'unequal'),
            (r'\bA[-a-z]+\b', 'non-word'),
            (r'\bA(?:ab)+\b', 'complex'),
            (r'\bA-[a-z]*\b', 'nullable'),
            (r'\bAKIA-B\b|\bAKIA\b', 'overlapping'),
        ]
        for pattern, reason in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(SystemExit, reason):
                    self.compile_rule(pattern)

    def test_generator_accepts_proved_shapes(self):
        for pattern in (r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
                        r'\bA[a-z]+\b', r'\bA[a-z]{2,4}\b',
                        r'\bA[a-z]{2}?\b', r'\bA(?:[a-z]+)\b',
                        r'\bA(?:-B|CD)\b'):
            with self.subTest(pattern=pattern):
                self.assertEqual(self.compile_rule(pattern)['end'], 'Boundary')
        self.assertEqual((self.directory / 'tables.rs').read_bytes(),
                         (ROOT / 'crates/ccs-redact/src/tables.rs').read_bytes())

    def test_generator_cli_refuses_audit_rules(self):
        source = (ROOT / 'vendor/memory-mcp/session_redact.py').read_text()
        original = r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'
        self.assertEqual(source.count(original), 1)
        for pattern, reason in ((r'\bAKIA[A-Z0-9]{16,}?\b', 'lazy'),
                                (r'\bAIza[0-9A-Za-z_-]{2,4}[a-z]\b', 'non-final'),
                                (r'\bAKIA(?:-B|)\b', 'unequal')):
            with self.subTest(pattern=pattern):
                oracle = self.directory / 'hypothetical.py'
                output = self.directory / 'hypothetical.rs'
                oracle.write_text(source.replace(original, pattern))
                result = subprocess.run([sys.executable, ARGS.generator, oracle, output],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, 'unsafe rule accepted by CLI')
                self.assertIn(reason, result.stderr)
                self.assertFalse(output.exists(), 'rejected rule left a generated table')

    def test_subsumed_optional_witnesses(self):
        cases = [
            # Audit witnesses: a lazy follower changes the overall spans.
            (r'(?:(?:ab)?[a-z]+?|z)b', r'(?:(?:ab)??[a-z]+?|z)b',
             'syn[0].a0[0]', 'swap-greed', 'abab'),
            (r'(?:(?:ab)?[a-z]+?|z)b', r'(?:(?:ab){0,2}[a-z]+?|z)b',
             'syn[0].a0[0]', 'hi+1', 'ababab'),
            # Identical overall spans are insufficient when captures differ.
            (r'(?:(ab)?[a-z]+|z)b', r'(?:(ab)??[a-z]+|z)b',
             'syn[0].a0[0]', 'swap-greed', 'abab'),
            # Captures inside assertions also change even with identical spans.
            (r'(?:(?:(?=(ab))ab)?[a-z]+|z)b', r'(?:(?:(?=(ab))ab)??[a-z]+|z)b',
             'syn[0].a0[0]', 'swap-greed', 'abab'),
            # An unbounded sequence is not necessarily a one-character class.
            (r'(?:a?(?:ab)+|z)b', r'(?:a{0,2}(?:ab)+|z)b',
             'syn[0].a0[0]', 'hi+1', 'aaabb'),
        ]
        for pattern, mutant, path, kind, text in cases:
            with self.subTest(pattern=pattern, kind=kind):
                before = [(m.span(), m.groups()) for m in re.finditer(pattern, text)]
                after = [(m.span(), m.groups()) for m in re.finditer(mutant, text)]
                self.assertNotEqual(before, after, 'witness must demonstrate non-equivalence')
                self.g.TREES['syn'] = (self.g.plain(self.g.P.parse(pattern)), False, False)
                self.assertFalse(self.predicates['subsumed_optional']('syn', path, kind))
                self.assertEqual(self.predicates['classify']('syn ' + path + ' ' + kind),
                                 'unresolved')

    def test_subsumed_optional_greedy_control(self):
        pattern = r'(?:(?:ab)?[a-z]+|z)b'
        self.g.TREES['syn'] = (self.g.plain(self.g.P.parse(pattern)), False, False)
        self.assertEqual(self.predicates['classify']('syn syn[0].a0[0] swap-greed'),
                         'subsumed-optional')
        for text in ('abab', 'ababab', 'ab', 'zb', 'aabb', 'aabbbb'):
            self.assertEqual([m.span() for m in re.finditer(pattern, text)],
                             [m.span() for m in re.finditer(r'(?:(?:ab)??[a-z]+|z)b', text)])


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]], verbosity=2)
