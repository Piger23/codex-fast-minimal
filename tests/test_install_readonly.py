"""Run the installer's check-only path with synthetic packages and mocked Appx state."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).parents[1]


def package(path, publisher, version):
    manifest = ('<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">'
                '<Identity Name="OpenAI.Codex" Publisher="' + publisher + '" Version="' + version + '" '
                'ProcessorArchitecture="x64"/></Package>').encode()
    digest = base64.b64encode(hashlib.sha256(manifest).digest()).decode()
    blockmap = ('<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
                'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"><File Name="AppxManifest.xml" '
                'Size="' + str(len(manifest)) + '"><Block Hash="' + digest + '"/></File></BlockMap>')
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr('AppxManifest.xml', manifest)
        z.writestr('AppxBlockMap.xml', blockmap)


@unittest.skipUnless(shutil.which('powershell.exe'), 'Windows PowerShell required')
class ReadOnlyInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        publisher = json.loads((REPO / 'profiles' / '26.930.3930.0.json').read_text())['publisher']
        self.plan = {'BaseVersion': '26.930.3930.0', 'FastVersion': '26.930.3930.1',
                     'RecoveryVersion': '26.930.3930.2', 'Publisher': publisher,
                     'CoreHash': hashlib.sha256((REPO / 'scripts' / 'fast_patch.py').read_bytes()).hexdigest()}
        for label, version in [('Fast', '26.930.3930.1'), ('Recovery', '26.930.3930.2')]:
            path = self.directory / (label.lower() + '-unsigned.msix')
            package(path, publisher, version)
            self.plan[label + 'Path'] = str(path)
            self.plan[label + 'Hash'] = hashlib.sha256(path.read_bytes()).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def run_check(self):
        (self.directory / 'plan.json').write_text(json.dumps(self.plan))
        env = dict(os.environ, FAST_TEST_ROOT=str(self.directory), FAST_TEST_REPO=str(REPO),
                   FAST_TEST_PYTHON=os.sys.executable)
        # Parent may be PowerShell 7, whose PSModulePath omits the 5.1 modules.
        for key in list(env):
            if key.upper() == 'PSMODULEPATH':
                del env[key]
        env['PSModulePath'] = str(Path(os.environ['SYSTEMROOT']) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'Modules')
        script = r'''
$ErrorActionPreference='Stop'
function Get-AppxPackage {
    $plan=Get-Content -Raw (Join-Path $env:FAST_TEST_ROOT 'plan.json') | ConvertFrom-Json
    [pscustomobject]@{Version='26.930.3930.0';Publisher=$plan.Publisher;SignatureKind='Store'}
}
function Add-AppxPackage {throw 'MUTATION ATTEMPT'}
function Stop-Process {throw 'MUTATION ATTEMPT'}
function New-SelfSignedCertificate {throw 'MUTATION ATTEMPT'}
function Import-Certificate {throw 'MUTATION ATTEMPT'}
try {
    & (Join-Path $env:FAST_TEST_REPO 'scripts/Install.ps1') -BuildDirectory $env:FAST_TEST_ROOT -Python $env:FAST_TEST_PYTHON
} catch {Write-Output $_.Exception.Message;exit 1}
'''
        return subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
                              env=env, capture_output=True, text=True, timeout=30)

    def test_check_only_does_not_mutate(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('CHECK-ONLY-OK', result.stdout)
        self.assertFalse((self.directory / 'installer.lock').exists())

    def test_modified_hash_refused(self):
        self.plan['FastHash'] = '0' * 64
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Artifact hash mismatch', result.stdout)

    def test_wrong_manifest_refused_even_with_matching_file_hash(self):
        path = Path(self.plan['FastPath'])
        package(path, self.plan['Publisher'], '26.930.3930.9')
        self.plan['FastHash'] = hashlib.sha256(path.read_bytes()).hexdigest()
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('MSIX identity mismatch', result.stdout)

    def run_cache_check(self, change=None):
        record = {'CertificateThumbprint': 'test-cert', 'SourceFastHash': self.plan['FastHash'],
                  'SourceRecoveryHash': self.plan['RecoveryHash'], 'Artifacts': []}
        for label in ('Fast', 'Recovery'):
            path = self.directory / (label.lower() + '-signed-1234abcd.msix')
            path.write_bytes(b'metadata-test-only')
            record[label+'Path'] = str(path)
            record['Artifacts'].append({'path': str(path), 'sha256': 'a'*64})
        if change:
            change(record)
        (self.directory/'cache.json').write_text(json.dumps(record))
        (self.directory/'plan.json').write_text(json.dumps(self.plan))
        script = r'''
$ErrorActionPreference='Stop'
try {
    $tokens=$null;$errors=$null
    $tree=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:FAST_TEST_REPO 'scripts/Install.ps1'),[ref]$tokens,[ref]$errors)
    if($errors.Count) {throw 'Installer syntax error'}
    $helper=$tree.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-SignedCache'},$true)
    Invoke-Expression $helper.Extent.Text
    $plan=Get-Content -Raw (Join-Path $env:FAST_TEST_ROOT 'plan.json') | ConvertFrom-Json
    $result=Read-SignedCache (Join-Path $env:FAST_TEST_ROOT 'cache.json') $env:FAST_TEST_ROOT $plan 'test-cert'
    if($null -eq $result) {Write-Output 'CACHE-MISS'} else {Write-Output 'CACHE-CANDIDATE-REQUIRES-FULL-REVALIDATION'}
} catch {Write-Output $_.Exception.Message;exit 1}
'''
        env = dict(os.environ, FAST_TEST_REPO=str(REPO), FAST_TEST_ROOT=str(self.directory))
        return subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                              env=env, capture_output=True, text=True, timeout=30)

    def test_signed_cache_metadata_matching_build(self):
        result = self.run_cache_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('REQUIRES-FULL-REVALIDATION', result.stdout)

    def test_signed_cache_other_certificate_or_source_is_not_reused(self):
        for key in ('CertificateThumbprint', 'SourceFastHash', 'SourceRecoveryHash'):
            result = self.run_cache_check(lambda record: record.update({key: 'different'}))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('CACHE-MISS', result.stdout)

    def test_signed_cache_outside_build_refused(self):
        result = self.run_cache_check(lambda record: record.update({'FastPath': str(self.directory.parent/'fast-signed-1234abcd.msix')}))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('outside this build', result.stdout)

    def test_signed_cache_incomplete_digest_refused(self):
        result = self.run_cache_check(lambda record: record.update({'Artifacts': []}))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Incomplete signed artifact digest', result.stdout)
