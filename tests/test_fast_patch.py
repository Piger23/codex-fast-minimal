import base64
import hashlib
import importlib.util
import json
import struct
import tempfile
import unittest
import zipfile
from unittest import mock
from pathlib import Path

spec = importlib.util.spec_from_file_location('fast_patch', Path(__file__).parents[1] / 'scripts' / 'fast_patch.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def archive(path, data=b'hello $$i old', dedup=True):
    integrity = {'algorithm': 'SHA256', 'hash': m.sha(data), 'blockSize': 4,
                 'blocks': [m.sha(data[i:i+4]) for i in range(0, len(data), 4)]}
    files = {'target.js': {'offset': '0', 'size': len(data), 'integrity': integrity},
             'empty': {'offset': str(len(data)), 'size': 0},
             'other': {'offset': str(len(data)), 'size': 3}}
    if dedup:
        files['alias'] = dict(files['other'])
    raw = json.dumps({'files': files}, separators=(',', ':')).encode()
    pad = b'\0' * (-len(raw) % 4)
    path.write_bytes(struct.pack('<IIII', 4, 8+len(raw)+len(pad), 4+len(raw)+len(pad), len(raw)) + raw + pad + data + b'xyz')
    return {'asset': 'target.js', 'original_sha256': m.sha(data),
            'patched_sha256': m.sha(data.replace(b'old', b'new-long')),
            'edits': [{'old': 'old', 'new': 'new-long'}]}


def msix(path, bad_hash=False, duplicate=False):
    data = b'a' * 70000
    hashes = [base64.b64encode(hashlib.sha256(data[i:i+65536]).digest()).decode()
              for i in range(0, len(data), 65536)]
    if bad_hash:
        hashes[0] = base64.b64encode(b'\0'*32).decode()
    blocks = ''.join('<Block Hash="' + h + '"/>' for h in hashes)
    xml = ('<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
           'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"><File Name="a" Size="70000">'
           + blocks + '</File></BlockMap>')
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr('a', data)
        z.writestr('AppxBlockMap.xml', xml)
        if duplicate:
            z.writestr('A', data)


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source.asar'
        self.output = self.root / 'output.asar'
        self.profile = archive(self.source)

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip_dedup_empty_literal_dollars(self):
        original = self.source.read_bytes()
        m.patch_archive(self.source, self.output, self.profile)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(m.verify_archive(self.source, self.output, self.profile)['entries_verified'], 4)
        tree, start, _ = m.read_header(self.output)
        self.assertEqual(m.entry_bytes(self.output, start, tree['files']['target.js']), b'hello $$i new-long')
        self.assertEqual(tree['files']['alias']['offset'], tree['files']['other']['offset'])
        with self.assertRaises(ValueError):
            m.patch_archive(self.source, self.output, self.profile)

    def test_reject_unknown_and_multiple_matches(self):
        with self.assertRaises(ValueError):
            m.transform(b'unknown', self.profile)
        data = b'old old'
        profile = dict(self.profile, original_sha256=m.sha(data))
        with self.assertRaises(ValueError):
            m.transform(data, profile)

    def test_unrelated_corruption_is_detected(self):
        m.patch_archive(self.source, self.output, self.profile)
        with self.output.open('r+b') as f:
            f.seek(-1, 2)
            f.write(b'!')
        with self.assertRaises(ValueError):
            m.verify_archive(self.source, self.output, self.profile)

    def test_launcher_changes_only_hash(self):
        m.patch_archive(self.source, self.output, self.profile)
        old = m.read_header(self.source)[2].encode()
        new = m.read_header(self.output)[2].encode()
        data = b'prefix{"file":"resources/app.asar","alg":"SHA256","value":"' + old + b'"}suffix'
        launcher = self.root / 'launcher'
        launcher.write_bytes(data)
        m.repair_launcher(self.source, self.output, launcher)
        self.assertEqual(launcher.read_bytes(), data.replace(old, new))
        with self.assertRaises(ValueError):
            m.repair_launcher(self.source, self.output, launcher)

    def test_msix_blocks_and_rejections(self):
        path = self.root / 'test.msix'
        msix(path)
        self.assertEqual(m.verify_msix(path)['payload_files_verified'], 1)
        for bad, duplicate in [(True, False), (False, True)]:
            msix(path, bad, duplicate)
            with self.assertRaises(ValueError):
                m.verify_msix(path)

    def test_serial_parallel_msix_results_and_failure(self):
        path = self.root / 'parallel.msix'
        msix(path)
        one, many = m.verify_msix(path, 1), m.verify_msix(path, 4)
        self.assertEqual(one['payload_files_verified'], many['payload_files_verified'])
        msix(path, bad_hash=True)
        with self.assertRaises(ValueError):
            m.verify_msix(path, 4)
        with self.assertRaises(ValueError):
            m.verify_msix(path, 0)

    def test_parallel_package_bundle_rejects_any_corrupt_member(self):
        from test_install_readonly import package
        good, bad = self.root / 'good.msix', self.root / 'bad.msix'
        package(good, 'CN=test', '1.2.3.4')
        package(bad, 'CN=test', '1.2.3.5')
        reports = m.verify_packages([good, bad], 4)
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0]['sha256'], m.file_hash(good))
        with zipfile.ZipFile(bad, 'a') as z:
            z.writestr('unmapped-data', b'bad')
        with self.assertRaises(ValueError):
            m.verify_packages([good, bad], 4)

    def test_parallel_scope_checks_full_file_set(self):
        source, target = self.root / 'original', self.root / 'copied'
        removed = ['AppxSignature.p7x', 'AppxBlockMap.xml', 'AppxMetadata/CodeIntegrity.cat']
        changed = ['AppxManifest.xml', 'app/ChatGPT.exe', 'app/resources/app.asar']
        for root in (source, target):
            for name in changed + ['unchanged']:
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b'old' if root == source or name == 'unchanged' else b'new')
        for name in removed:
            p = source / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b'original-signature')
        report = m.verify_scope(source, target, 4)
        self.assertEqual(report['files_compared'], 4)
        (target / 'unchanged').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            m.verify_scope(source, target, 4)

    def test_signing_worker_failure_is_propagated(self):
        source = self.root / 'unsigned'
        source.write_bytes(b'payload')
        plan = self.root / 'sign.json'
        plan.write_text(json.dumps({'signtool': 'not-run', 'thumbprint': 'public-id', 'jobs': [
            {'source': str(source), 'destination': str(self.root/'signed'), 'sha256': m.file_hash(source)}]}))
        with mock.patch.object(m.subprocess, 'run', return_value=mock.Mock(returncode=1)):
            with self.assertRaises(ValueError):
                m.sign_packages(plan, 2)

    def signing_plan(self, jobs):
        path = self.root / 'sign.json'
        path.write_text(json.dumps({'signtool': 'not-run', 'thumbprint': 'public-id', 'jobs': jobs}))
        return path

    def test_verified_copy_hashes_copied_bytes_without_second_read(self):
        data = b'copy-boundary-' * (9 * 1024 * 1024 // 14 + 1)
        source, destination = self.root/'unsigned', self.root/'signed'
        source.write_bytes(data)
        with mock.patch.object(m, 'file_hash', side_effect=AssertionError('extra whole-file read')):
            m.copy_verified(source, destination, m.sha(data))
        self.assertEqual(source.read_bytes(), data)
        self.assertEqual(destination.read_bytes(), data)
        with self.assertRaises(FileExistsError):
            m.copy_verified(source, destination, m.sha(data))
        self.assertEqual(destination.read_bytes(), data)

    def test_wrong_copy_digest_prevents_every_signer(self):
        jobs = []
        for index in range(2):
            source = self.root / ('source' + str(index))
            source.write_bytes(b'payload')
            jobs.append({'source': str(source), 'destination': str(self.root/('signed'+str(index))),
                         'sha256': m.sha(b'payload') if index == 0 else '0'*64})
        with mock.patch.object(m.subprocess, 'run') as signer:
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                m.sign_packages(self.signing_plan(jobs), 2)
            signer.assert_not_called()

    def test_signing_copies_finish_before_signers_and_report_timings(self):
        jobs = []
        for index in range(2):
            source = self.root / ('source' + str(index))
            source.write_bytes(b'payload')
            jobs.append({'source': str(source), 'destination': str(self.root/('signed'+str(index))),
                         'sha256': m.sha(b'payload')})
        def fake_sign(args, **kwargs):
            self.assertTrue(all(Path(job['destination']).exists() for job in jobs))
            self.assertEqual(args[1:4], ['sign', '/fd', 'SHA256'])
            self.assertNotIn('/t', args)
            self.assertNotIn('/tr', args)
            return mock.Mock(returncode=0)
        with mock.patch.object(m.subprocess, 'run', side_effect=fake_sign) as signer:
            report = m.sign_packages(self.signing_plan(jobs), 2)
        self.assertEqual(signer.call_count, 2)
        self.assertEqual(report['paths'], [job['destination'] for job in jobs])
        self.assertEqual(report['sign_workers'], 2)
        self.assertGreaterEqual(report['copy_and_sha256_seconds'], 0)
        self.assertGreaterEqual(report['signtool_seconds'], 0)

    def test_signing_rejects_collisions_before_copying(self):
        source = self.root / 'source'
        source.write_bytes(b'original')
        for outputs in [(source, self.root/'other'), (self.root/'same', self.root/'same')]:
            jobs = [{'source': str(source), 'destination': str(path), 'sha256': m.sha(b'original')}
                    for path in outputs]
            with self.assertRaises(ValueError):
                m.sign_packages(self.signing_plan(jobs), 2)
            self.assertEqual(source.read_bytes(), b'original')
        self.assertFalse((self.root/'same').exists())

    def test_streaming_chunk_boundary_crc_and_archive_hash(self):
        from test_install_readonly import package
        path = self.root / 'boundary.msix'
        data = b'chunk-boundary-' * (9 * 1024 * 1024 // 15 + 1)
        hashes = [base64.b64encode(hashlib.sha256(data[i:i+65536]).digest()).decode()
                  for i in range(0, len(data), 65536)]
        xml = ('<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
               'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"><File Name="payload" Size="'
               + str(len(data)) + '">' + ''.join('<Block Hash="'+h+'"/>' for h in hashes) + '</File></BlockMap>')
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr('payload', data)
            z.writestr('AppxBlockMap.xml', xml, compress_type=zipfile.ZIP_DEFLATED)
        report = m.verify_msix(path, 4)
        self.assertEqual(report['archive_sha256'], m.file_hash(path))
        self.assertEqual(report['method'], 'sequential_io_parallel_sha256_crc')
        raw = bytearray(path.read_bytes())
        central = raw.index(b'PK\x01\x02')
        raw[central+16] ^= 1  # Corrupt the central CRC without changing the mapped payload.
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            m.verify_msix(path, 4)

    def test_recovery_manifest_and_store_blockmap_scope(self):
        from test_install_readonly import package
        source = self.root / 'store'
        source.mkdir()
        original, recovery = self.root/'store.msix', self.root/'recovery.msix'
        package(original, 'CN=test', '1.2.3.0')
        package(recovery, 'CN=test', '1.2.3.2')
        with zipfile.ZipFile(original) as z:
            for name in ('AppxManifest.xml', 'AppxBlockMap.xml'):
                (source/name).write_bytes(z.read(name))
        self.assertTrue(m.verify_package_scope(source, recovery)['manifest_only_version_changed'])
        package(recovery, 'CN=changed', '1.2.3.2')
        with self.assertRaises(ValueError):
            m.verify_package_scope(source, recovery)


if __name__ == '__main__':
    unittest.main()
