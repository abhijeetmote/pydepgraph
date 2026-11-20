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

    def test_invalid_profile_shapes(self):
        for invalid in (None, [], dict(id='x',environment={'python_verison':'3.12'}),
                        profile(extras=[''])):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_profile(invalid)

    def test_unknown_snapshot_profile_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            analyze(tmp, [profile()], snapshots={'typo': {}})

    def test_unknown_snapshot_repository_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            analyze(tmp, [profile()], snapshots={'linux': {'missing': 'unused.json'}})

    def test_reconciliation_is_advisory_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'repos'; repo=root/'app'; repo.mkdir(parents=True)
            (repo/'requirements.txt').write_text('good>=1,<3\nbad==1\nmissing==1\ninactive==1; sys_platform == "win32"\nunknown==1; platform_machine == "arm64"\n')
            p=profile(); snap=Path(tmp)/'inspect.json'
            snap.write_text(json.dumps(dict(version='1',environment=p['environment'],installed=[
                dict(metadata={'name':name,'version':'2'}) for name in ['good','bad','inactive','tool']
            ])))
            result=analyze(root,[p],snapshots={'linux':{'app':str(snap)}})['results'][0]
            self.assertEqual({r['package']:r['relation'] for r in result['comparisons']}, {
                'good':'satisfies_declaration','bad':'violates_declaration','missing':'active_absent',
                'inactive':'inactive_present','unknown':'unresolved_applicability','tool':'inventory_only'})
            self.assertEqual(result['findings'],[])

    def test_snapshot_without_supported_declarations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'repos'; (root/'app').mkdir(parents=True)
            p=profile(); snap=Path(tmp)/'inspect.json'
            snap.write_text(json.dumps(dict(version='1',environment=p['environment'],installed=[
                dict(metadata={'name':'tool','version':'1'})])))
            result=analyze(root,[p],snapshots={'linux':{'app':str(snap)}})['results'][0]
            self.assertEqual(result['comparisons'][0]['relation'],'inventory_only')

    def test_conflicting_declarations_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'repos'; repo=root/'app'; repo.mkdir(parents=True)
            (repo/'requirements.txt').write_text('demo==1\ndemo==2\n')
            p=profile(); snap=Path(tmp)/'inspect.json'
            snap.write_text(json.dumps(dict(version='1',environment=p['environment'],installed=[
                dict(metadata={'name':'demo','version':'2'})])))
            result=analyze(root,[p],snapshots={'linux':{'app':str(snap)}})['results'][0]
            self.assertEqual({r['relation'] for r in result['comparisons']},
                             {'satisfies_declaration','violates_declaration'})

if __name__=='__main__':unittest.main()
