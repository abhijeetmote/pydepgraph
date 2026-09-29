import json
import tempfile
import unittest
from pathlib import Path
from pydepgraph import scan


class ScannerTests(unittest.TestCase):
    def run_case(self, files, environment=None):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / 'app'
            repo.mkdir()
            (repo / 'pydepgraph.json').write_text(json.dumps({'environment': environment or {'sys_platform': 'linux'}}))
            for name, content in files.items():
                (repo / name).write_text(content)
            return scan(tmp, [{'id': 'SYNTH-001', 'package': 'demo-lib', 'affected': '<2', 'synthetic': True}])

    def test_pin_and_range(self):
        result = self.run_case({'requirements.txt': 'demo-lib==1.0\ndemo-lib>=1\n'})
        self.assertEqual([x['status'] for x in result['findings']], ['affected', 'indeterminate'])

    def test_marker(self):
        result = self.run_case({'requirements.txt': 'demo-lib==1; sys_platform == "win32"'})
        self.assertFalse(result['rows'][0]['active'])
        self.assertEqual(result['findings'], [])

    def test_unknown_marker(self):
        result = self.run_case({'requirements.txt': 'demo-lib==1; python_version < "3.12"'})
        self.assertIsNone(result['rows'][0]['active'])
        self.assertEqual(result['findings'][0]['status'], 'indeterminate')

    def test_constraints_not_usage(self):
        result = self.run_case({'requirements.txt': '-c bounds.txt\ndemo-lib>=1', 'bounds.txt': 'demo-lib==1'})
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['status'], 'indeterminate')

    def test_include_cycle(self):
        result = self.run_case({'requirements.txt': '-r deps.txt', 'deps.txt': '-r requirements.txt\ndemo-lib==1'})
        self.assertEqual(len(result['rows']), 1)

    def test_escape(self):
        result = self.run_case({'requirements.txt': '-r ../outside.txt'})
        self.assertIn('rejected', result['diagnostics'][0]['message'])

    def test_normalization_and_hash(self):
        result = self.run_case({'requirements.txt': 'Demo_Lib==2.0 --hash=sha256:abc'})
        self.assertEqual(result['rows'][0]['package'], 'demo-lib')
        self.assertEqual(result['findings'][0]['status'], 'not_affected')

    def test_bad_toml(self):
        result = self.run_case({'pyproject.toml': '[bad'})
        self.assertEqual(len(result['diagnostics']), 1)

    def test_ini_dev_scope(self):
        result = self.run_case({'tox.ini': '[testenv]\ndeps =\n demo-lib==1\n'})
        self.assertEqual(result['rows'][0]['scope'], 'testenv')

    def test_pipfile_marker(self):
        result = self.run_case({'Pipfile.lock': json.dumps({'default': {'demo-lib': {'version': '==1', 'markers': 'sys_platform == "win32"'}}})})
        self.assertEqual(result['findings'], [])

    def test_optional_preserved(self):
        result = self.run_case({'pyproject.toml': '[project.optional-dependencies]\nweb = ["demo-lib==1"]'})
        self.assertEqual(result['rows'][0]['scope'], 'optional:web')

    def test_no_cross_repository_conflict(self):
        result = self.run_case({'requirements.txt': 'demo-lib==1', 'poetry.lock': '[[package]]\nname="demo-lib"\nversion="2"'})
        self.assertEqual({x['evidence'] for x in result['rows']}, {'locked', 'declared'})
        self.assertEqual(len(result['rows']), 2)


if __name__ == '__main__':
    unittest.main()
