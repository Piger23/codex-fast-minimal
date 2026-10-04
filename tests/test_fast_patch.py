import base64
import hashlib
import importlib.util
import json
import struct
import tempfile
import unittest
import zipfile
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


if __name__ == '__main__':
    unittest.main()
