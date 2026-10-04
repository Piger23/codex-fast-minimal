"""Small, version-pinned ASAR transform. Standard library only; no network calls."""
import argparse
import base64
import hashlib
import json
import re
import struct
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_header(path):
    with Path(path).open('rb') as handle:
        prefix = handle.read(16)
        if len(prefix) != 16 or struct.unpack_from('<I', prefix)[0] != 4:
            raise ValueError('Unsupported ASAR prefix')
        pickle_length, payload_length, json_length = struct.unpack_from('<III', prefix, 4)
        if pickle_length != payload_length + 4 or not 0 < json_length <= pickle_length - 8 < 64 * 1024 * 1024:
            raise ValueError('Invalid ASAR header size')
        raw = handle.read(json_length)
        tree = json.loads(raw.decode('utf-8'))
    encoded = json.dumps(tree, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if encoded != raw:
        raise ValueError('Header cannot be serialized identically; archive untouched')
    return tree, 8 + pickle_length, sha(raw)


def entries(tree, prefix=''):
    for name, entry in tree.get('files', {}).items():
        path = prefix + name
        if 'files' in entry:
            yield from entries(entry, path + '/')
        else:
            yield path, entry


def entry_bytes(path, start, entry):
    with Path(path).open('rb') as handle:
        handle.seek(start + int(entry['offset']))
        data = handle.read(entry['size'])
    if len(data) != entry['size']:
        raise ValueError('Truncated packed file')
    return data


def transform(data, profile):
    if sha(data) == profile['patched_sha256']:
        raise ValueError('Already patched; no file written')
    if sha(data) != profile['original_sha256']:
        raise ValueError('Unknown asset hash; refusing to patch')
    result = data
    for edit in profile['edits']:
        old, new = edit['old'].encode(), edit['new'].encode()
        if result.count(old) != 1:
            raise ValueError('Patch target must match exactly once')
        # Literal replacement preserves identifiers containing dollar signs.
        result = result.replace(old, new, 1)
    if sha(result) != profile['patched_sha256']:
        raise ValueError('Patched asset hash mismatch')
    return result


def inspect(path, profile):
    tree, start, header_hash = read_header(path)
    index = dict(entries(tree))
    target = index.get(profile['asset'])
    if not target or target.get('unpacked') or 'link' in target:
        raise ValueError('Profile target is not a packed file')
    data = entry_bytes(path, start, target)
    if target.get('integrity', {}).get('hash') != sha(data):
        raise ValueError('Original target integrity mismatch')
    transform(data, profile)
    return {'asset': profile['asset'], 'original_sha256': sha(data), 'header_sha256': header_hash}


def patch_archive(source, output, profile):
    source, output = Path(source).resolve(), Path(output).resolve()
    if source == output or output.exists():
        raise ValueError('Output must be new and separate from the source')
    tree, start, _ = read_header(source)
    file_map = dict(entries(tree))
    inspect(source, profile)
    target = file_map[profile['asset']]
    replacement = transform(entry_bytes(source, start, target), profile)
    ranges = {}
    for name, entry in file_map.items():
        if 'offset' in entry and not entry.get('unpacked'):
            ranges.setdefault((int(entry['offset']), entry['size']), []).append(name)
    cursor, old_end, plan = 0, 0, []
    for (offset, size), names in sorted(ranges.items()):
        if size and offset != old_end:
            raise ValueError('Packed ranges overlap or contain holes')
        if not size and offset > old_end:
            raise ValueError('Invalid empty range')
        changed = profile['asset'] in names
        if changed and len(names) != 1:
            raise ValueError('Cannot replace a deduplicated target')
        for name in names:
            file_map[name]['offset'] = str(cursor)
        if changed:
            block_size = target['integrity']['blockSize']
            if not isinstance(block_size, int) or block_size <= 0:
                raise ValueError('Invalid integrity block size')
            target['size'] = len(replacement)
            target['integrity'] = {'algorithm': 'SHA256', 'hash': sha(replacement),
                'blockSize': block_size, 'blocks': [sha(replacement[i:i+block_size]) for i in range(0, len(replacement), block_size)]}
            plan.append((None, replacement))
            cursor += len(replacement)
        elif size:
            plan.append((start + offset, size))
            cursor += size
        old_end = max(old_end, offset + size)
    if start + old_end != source.stat().st_size:
        raise ValueError('Unexpected trailing data')
    raw = json.dumps(tree, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    padding = b'\0' * (-len(raw) % 4)
    header = struct.pack('<IIII', 4, 8 + len(raw) + len(padding), 4 + len(raw) + len(padding), len(raw)) + raw + padding
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source.open('rb') as inp, output.open('xb') as out:
            out.write(header)
            for offset, value in plan:
                if offset is None:
                    out.write(value)
                    continue
                inp.seek(offset)
                left = value
                while left:
                    block = inp.read(min(left, 4 * 1024 * 1024))
                    if not block:
                        raise ValueError('Truncated original range')
                    out.write(block)
                    left -= len(block)
        verify_archive(source, output, profile)
    except BaseException:
        if output.exists():
            output.unlink()
        raise
    return {'patched_asset': profile['asset'], 'header_sha256': sha(raw)}


def verify_archive(source, output, profile):
    a, sa, _ = read_header(source)
    b, sb, _ = read_header(output)
    aa, bb = dict(entries(a)), dict(entries(b))
    if set(aa) != set(bb):
        raise ValueError('Archive entry set changed')
    for name, entry in aa.items():
        other = bb[name]
        expected = dict(entry)
        actual = dict(other)
        expected.pop('offset', None)
        actual.pop('offset', None)
        if name == profile['asset']:
            expected.pop('size', None); actual.pop('size', None)
            expected.pop('integrity', None); actual.pop('integrity', None)
        if expected != actual:
            raise ValueError('Unexpected metadata change: ' + name)
        if 'offset' in entry and not entry.get('unpacked'):
            old, new = entry_bytes(source, sa, entry), entry_bytes(output, sb, other)
            if name == profile['asset']:
                if new != transform(old, profile):
                    raise ValueError('Target differs from exact Fast patch')
            elif old != new:
                raise ValueError('Unexpected content change: ' + name)
    return {'entries_verified': len(aa), 'changed': [profile['asset']]}


def repair_launcher(original_asar, patched_asar, launcher):
    original_hash = read_header(original_asar)[2].encode()
    patched_hash = read_header(patched_asar)[2].encode()
    path = Path(launcher)
    data = path.read_bytes()
    pattern = rb'\{"file":"resources(?:\\\\|/)app\.asar","alg":"SHA256","value":"([a-fA-F0-9]{64})"\}'
    matches = list(re.finditer(pattern, data))
    if len(matches) != 1 or matches[0].group(1).lower() != original_hash:
        raise ValueError('Launcher integrity format/hash is unsupported')
    start, end = matches[0].span(1)
    path.write_bytes(data[:start] + patched_hash + data[end:])
    return {'launcher_header_sha256': patched_hash.decode()}


def verify_msix(path):
    allowed = {'appxblockmap.xml', 'appxsignature.p7x', '[content_types].xml', 'appxmetadata\\codeintegrity.cat'}
    with zipfile.ZipFile(path) as archive:
        index = {}
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            name = urllib.parse.unquote(entry.filename).replace('/', '\\').lower()
            if name in index:
                raise ValueError('Duplicate ZIP entry')
            index[name] = entry
        map_entry = index['appxblockmap.xml']
        if map_entry.file_size > 64 * 1024 * 1024:
            raise ValueError('Unbounded block map')
        raw = archive.read(map_entry)
        if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
            raise ValueError('DTD/entities are forbidden')
        root = ET.fromstring(raw)
        ns = '{http://schemas.microsoft.com/appx/2010/blockmap}'
        if root.tag != ns+'BlockMap' or root.get('HashMethod') != 'http://www.w3.org/2001/04/xmlenc#sha256':
            raise ValueError('Unsupported block map')
        seen = set()
        for file in root.findall(ns+'File'):
            name = file.attrib['Name'].lower()
            if name in seen:
                raise ValueError('Duplicate mapped file')
            seen.add(name)
            entry = index[name]
            left = int(file.attrib['Size'])
            if left < 0 or left != entry.file_size:
                raise ValueError('Mapped size mismatch')
            with archive.open(entry) as stream:
                for block in file.findall(ns+'Block'):
                    if left <= 0:
                        raise ValueError('Extra block')
                    data = stream.read(min(left, 65536))
                    if not data or base64.b64encode(hashlib.sha256(data).digest()).decode() != block.attrib['Hash']:
                        raise ValueError('Payload block mismatch')
                    left -= len(data)
                if left or stream.read(1):
                    raise ValueError('Missing block')
        if not seen or set(index) - seen - allowed:
            raise ValueError('Unmapped payload')
    return {'payload_files_verified': len(seen)}


def package_identity(path):
    with zipfile.ZipFile(path) as archive:
        item = archive.getinfo('AppxManifest.xml')
        if item.file_size > 1024 * 1024:
            raise ValueError('Manifest too large')
        raw = archive.read(item)
    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise ValueError('DTD/entities are forbidden')
    root = ET.fromstring(raw)
    identity = root.find('{http://schemas.microsoft.com/appx/manifest/foundation/windows10}Identity')
    if identity is None:
        raise ValueError('Missing package identity')
    return dict(identity.attrib)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'patch', 'verify', 'launcher', 'msix', 'identity'])
    parser.add_argument('paths', nargs='+')
    parser.add_argument('--profile', type=Path)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text()) if args.profile else None
    if args.action not in ('msix', 'launcher', 'identity') and not profile:
        parser.error('--profile is required')
    functions = {'inspect': lambda: inspect(*args.paths, profile), 'patch': lambda: patch_archive(*args.paths, profile),
        'verify': lambda: verify_archive(*args.paths, profile), 'launcher': lambda: repair_launcher(*args.paths),
        'msix': lambda: verify_msix(*args.paths), 'identity': lambda: package_identity(*args.paths)}
    print(json.dumps(functions[args.action](), indent=2))


if __name__ == '__main__':
    main()
