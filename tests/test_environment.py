import json
import tempfile
import unittest
from pathlib import Path
from environment_analysis import applicability, analyze, inspect_snapshot, validate_profile


def row(marker=None, scope='runtime'):
    return dict(marker=marker, scope=scope)


def profile(**kwargs):
    return dict(id='linux', environment={'sys_platform': 'linux', 'python_version': '3.12'}, **kwargs)


class EnvironmentTests(unittest.TestCase):
    def test_marker_target_not_host(self):
        self.assertEqual(applicability(row('sys_platform == "win32"'), profile())[0], False)

    def test_unknown_not_host_default(self):
        self.assertIsNone(applicability(row('platform_machine == "arm64"'), profile())[0])

    def test_quoted_variable_word_is_not_variable(self):
        self.assertTrue(applicability(row('sys_platform != "python_version"'), dict(id='x', environment={'sys_platform':'linux'}))[0])

    def test_optional_selection(self):
        self.assertIsNone(applicability(row(scope='optional:web'), profile())[0])
        self.assertFalse(applicability(row(scope='optional:web'), profile(extras=[]))[0])
        self.assertTrue(applicability(row(scope='optional:my-web'), profile(extras=['my_web']))[0])

    def test_groups(self):
        self.assertFalse(applicability(row(scope='group:test'), profile(groups=[]))[0])
        self.assertTrue(applicability(row(scope='group:test'), profile(groups=['test']))[0])

    def test_extra_context_union(self):
        self.assertTrue(applicability(row('extra == "web"'), profile(extras=['cli','web']))[0])
        self.assertTrue(applicability(row('extra != "web"'), profile(extras=['web']))[0])
        self.assertFalse(applicability(row('extra == "web"'), profile(extras=[]))[0])

    def test_lock_scope_unknown(self):
        self.assertIsNone(applicability(row(scope='lock'), profile())[0])

    def test_constraint_not_usage(self):
        self.assertFalse(applicability(row(scope='constraint'), profile())[0])

    def test_inconsistent_python_rejected(self):
        with self.assertRaises(ValueError):
            validate_profile(dict(id='bad', environment={'python_version':'3.12','python_full_version':'3.11.9'}))

    def test_reserved_context_rejected(self):
        with self.assertRaises(ValueError):
            validate_profile(dict(id='bad', environment={'extra':'web'}))

    def test_snapshot_and_declaration_remain_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'repos'; repo=root/'app'; repo.mkdir(parents=True)
            (repo/'requirements.txt').write_text('demo==1\n')
            p=profile(); snap=Path(tmp)/'inspect.json'
            snap.write_text(json.dumps(dict(version='1', environment=p['environment'], installed=[dict(metadata={'name':'demo','version':'2'})])))
            r=analyze(root,[p],[dict(id='SYNTH',package='demo',affected='<2',synthetic=True)],{'linux':{'app':str(snap)}})['results'][0]
            self.assertEqual(r['findings'][0]['status'],'affected')
            self.assertEqual(r['observations'][0]['status'],'not_affected')
            self.assertEqual(len(r['observations'][0]['snapshot_sha256']),64)
            snap.write_text(json.dumps(dict(version='1',environment={'sys_platform':'win32'},installed=[])))
            with self.assertRaises(ValueError):inspect_snapshot(snap,p)

    def test_duplicate_profiles_rejected(self):
        with self.assertRaises(ValueError):analyze('.', [profile(),profile()])

    def test_range_stays_indeterminate(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'app';p.mkdir();(p/'requirements.txt').write_text('demo>=1')
            r=analyze(tmp,[profile()],[dict(id='x',package='demo',affected='<2')])
            self.assertEqual(r['results'][0]['findings'][0]['status'],'indeterminate')

if __name__=='__main__':unittest.main()
