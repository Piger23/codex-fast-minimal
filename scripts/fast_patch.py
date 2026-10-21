"""Small, version-pinned ASAR transform. Standard library only; no network calls."""
import argparse
import base64
import hashlib
import json
import mmap
import os
import re
import struct
import subprocess
import time
import zlib
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
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


def patch_archive(source, output, profile, workers=4):
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
            # Coalesce adjacent unchanged entries instead of 20k seek/read pairs.
            if plan and plan[-1][0] is not None and plan[-1][0] + plan[-1][1] == start + offset:
                previous, length = plan[-1]
                plan[-1] = (previous, length + size)
            else:
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
        verification = verify_archive(source, output, profile, workers)
    except BaseException:
        if output.exists():
            output.unlink()
        raise
    return {'patched_asset': profile['asset'], 'header_sha256': sha(raw), 'verification': verification}


def verify_archive(source, output, profile, workers=4):
    a, sa, _ = read_header(source)
    b, sb, _ = read_header(output)
    aa, bb = dict(entries(a)), dict(entries(b))
    if set(aa) != set(bb):
        raise ValueError('Archive entry set changed')
    comparisons = []
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
            if name == profile['asset']:
                old, new = entry_bytes(source, sa, entry), entry_bytes(output, sb, other)
                if new != transform(old, profile):
                    raise ValueError('Target differs from exact Fast patch')
                if other.get('integrity', {}).get('hash') != sha(new):
                    raise ValueError('Patched target integrity mismatch')
            else:
                if entry['size'] != other['size']:
                    raise ValueError('Unexpected size change: ' + name)
                for offset in range(0, entry['size'], 4 * 1024 * 1024):
                    length = min(4 * 1024 * 1024, entry['size'] - offset)
                    comparisons.append((name, sa + int(entry['offset']) + offset,
                                        sb + int(other['offset']) + offset, length))
    # Shared read-only mappings; no 40k file opens and no mutable shared seek position.
    with open(source, 'rb') as fa, open(output, 'rb') as fb:
        with mmap.mmap(fa.fileno(), 0, access=mmap.ACCESS_READ) as ma, mmap.mmap(fb.fileno(), 0, access=mmap.ACCESS_READ) as mb:
            def compare(batch):
                for name, x, y, length in batch:
                    if x < 0 or y < 0 or x + length > len(ma) or y + length > len(mb):
                        raise ValueError('Truncated archive entry: ' + name)
                    if ma[x:x+length] != mb[y:y+length]:
                        raise ValueError('Unexpected content change: ' + name)
            batches = [comparisons[i:i+128] for i in range(0, len(comparisons), 128)]
            with ThreadPoolExecutor(max_workers=worker_count(workers)) as pool:
                list(pool.map(compare, batches))
    return {'entries_verified': len(aa), 'changed': [profile['asset']], 'workers': worker_count(workers)}


def worker_count(workers):
    if not isinstance(workers, int) or not 1 <= workers <= 16:
        raise ValueError('Workers must be between 1 and 16')
    return min(workers, os.cpu_count() or 1)


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def hash_paths(paths, workers=4):
    with ThreadPoolExecutor(max_workers=worker_count(workers)) as pool:
        return dict(zip(map(str, paths), pool.map(file_hash, paths)))


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


def scan_stored_msix(path, archive, jobs, workers):
    """One sequential disk pass, bounded parallel SHA256, retaining every CRC.

    MakeAppx /nc stores payloads but compresses small XML footprints. Large
    compressed entries/ZIP64 local headers retain the general ZipFile verifier.
    """
    infos = [i for i in archive.infolist() if not i.is_dir()]
    if any(i.compress_type != zipfile.ZIP_STORED and i.file_size > 8 * 1024 * 1024 for i in infos):
        return None
    regions = {}
    with open(path, 'rb') as stream:
        for info in sorted(infos, key=lambda i: i.header_offset):
            stream.seek(info.header_offset)
            header = stream.read(30)
            if len(header) != 30 or header[:4] != b'PK\x03\x04':
                raise ValueError('Invalid ZIP local header')
            fields = struct.unpack('<4s5H3I2H', header)
            flags, compression, crc, packed, size, name_length, extra_length = fields[2], fields[3], fields[6], fields[7], fields[8], fields[9], fields[10]
            if packed == 0xffffffff or size == 0xffffffff:
                return None
            name = stream.read(name_length).decode('utf-8' if flags & 0x800 else 'cp437')
            if '\0' in name or name != info.orig_filename or compression != info.compress_type or flags != info.flag_bits or flags & 0x61:
                raise ValueError('ZIP local/central header mismatch')
            if info.compress_type == zipfile.ZIP_STORED and info.compress_size != info.file_size:
                raise ValueError('Stored ZIP entry size mismatch')
            if not flags & 8 and (crc != info.CRC or packed != info.compress_size or size != info.file_size):
                raise ValueError('ZIP local/central size or CRC mismatch')
            start = info.header_offset + 30 + name_length + extra_length
            end = start + info.compress_size
            if end > archive.start_dir or start < info.header_offset:
                raise ValueError('ZIP entry overlaps central directory')
            regions[info.filename] = (start, end, info)
    ordered = sorted(regions.values(), key=lambda item: item[0])
    for previous, following in zip(ordered, ordered[1:]):
        if previous[1] > following[2].header_offset:
            raise ValueError('Overlapping ZIP entries')
    chunk_size = 8 * 1024 * 1024
    blocks_by_chunk = defaultdict(list)
    for filename, length, hashes in jobs:
        start, end, info = regions[filename]
        if len(hashes) != (length + 65535) // 65536:
            raise ValueError('Missing/extra mapped blocks')
        if info.compress_type != zipfile.ZIP_STORED:
            data = archive.read(info)  # Includes decompression and full CRC check.
            for offset, expected in zip(range(0, length, 65536), hashes):
                if base64.b64encode(hashlib.sha256(data[offset:offset+65536]).digest()).decode() != expected:
                    raise ValueError('Payload block mismatch: ' + filename)
            continue
        for i, expected in enumerate(hashes):
            offset = start + i * 65536
            count = min(65536, length - i * 65536)
            blocks_by_chunk[(offset + count - 1) // chunk_size].append((offset, count, expected))
    stored = [r for r in ordered if r[2].compress_type == zipfile.ZIP_STORED]
    for start, end, info in ordered:
        if info.compress_type != zipfile.ZIP_STORED:
            archive.read(info)  # Also validate CRC of unmapped XML/signature footprints.
        elif start == end and info.CRC != 0:
            raise ValueError('Empty ZIP entry CRC mismatch')
    crcs = {}
    digest = hashlib.sha256()
    def check_blocks(data, base, checks):
        for offset, length, expected in checks:
            position = offset - base
            if position < 0 or position + length > len(data):
                raise ValueError('Missing streamed payload bytes')
            actual = base64.b64encode(hashlib.sha256(data[position:position+length]).digest()).decode()
            if actual != expected:
                raise ValueError('Payload block mismatch')
    pending, region_index, position, chunk_index, tail = deque(), 0, 0, 0, b''
    with open(path, 'rb') as stream, ThreadPoolExecutor(max_workers=worker_count(workers)) as pool:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
            end_position = position + len(chunk)
            while region_index < len(stored) and stored[region_index][1] <= position:
                region_index += 1
            j = region_index
            while j < len(stored) and stored[j][0] < end_position:
                begin, end, info = stored[j]
                lo, hi = max(begin, position), min(end, end_position)
                if hi > lo:
                    crcs[info.filename] = zlib.crc32(memoryview(chunk)[lo-position:hi-position], crcs.get(info.filename, 0))
                    if hi == end and crcs[info.filename] != info.CRC:
                        raise ValueError('ZIP payload CRC mismatch: ' + info.filename)
                j += 1
            checks = blocks_by_chunk.pop(chunk_index, [])
            if checks:
                pending.append(pool.submit(check_blocks, tail + chunk, position-len(tail), checks))
                if len(pending) >= worker_count(workers) * 2:
                    pending.popleft().result()
            tail = chunk[-65536:]
            position, chunk_index = end_position, chunk_index + 1
        for future in pending:
            future.result()
    if blocks_by_chunk or position != Path(path).stat().st_size:
        raise ValueError('Truncated or changing package')
    return digest.hexdigest()


def verify_msix(path, workers=4):
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
        jobs = []
        for file in root.findall(ns+'File'):
            name = file.attrib['Name'].lower()
            if name in seen:
                raise ValueError('Duplicate mapped file')
            seen.add(name)
            entry = index[name]
            left = int(file.attrib['Size'])
            if left < 0 or left != entry.file_size:
                raise ValueError('Mapped size mismatch')
            jobs.append((entry.filename, left, [block.attrib['Hash'] for block in file.findall(ns+'Block')]))
        if not seen or set(index) - seen - allowed:
            raise ValueError('Unmapped payload')
        digest = scan_stored_msix(path, archive, jobs, workers)
        if digest is not None:
            return {'payload_files_verified': len(seen), 'workers': worker_count(workers),
                    'archive_sha256': digest, 'method': 'sequential_io_parallel_sha256_crc'}
        def check_batch(batch):
            # Independent handles per worker avoid ZipFile's shared read lock.
            with zipfile.ZipFile(path) as local:
                for name, left, hashes in batch:
                    with local.open(name) as stream:
                        for expected_hash in hashes:
                            if left <= 0:
                                raise ValueError('Extra block')
                            data = stream.read(min(left, 65536))
                            if not data or base64.b64encode(hashlib.sha256(data).digest()).decode() != expected_hash:
                                raise ValueError('Payload block mismatch: ' + name)
                            left -= len(data)
                        if left or stream.read(1):
                            raise ValueError('Missing block: ' + name)
        buckets = [[] for _ in range(worker_count(workers))]
        loads = [0] * len(buckets)
        for job in sorted(jobs, key=lambda item: item[1], reverse=True):
            target = min(range(len(loads)), key=loads.__getitem__)
            buckets[target].append(job)
            loads[target] += job[1]
        with ThreadPoolExecutor(max_workers=len(buckets)) as pool:
            list(pool.map(check_batch, [batch for batch in buckets if batch]))
    return {'payload_files_verified': len(seen), 'workers': worker_count(workers)}


def verify_packages(paths, workers=4):
    """Sequential archive reads prevent HDD seek thrashing; hashes run in parallel."""
    budget = worker_count(workers)
    def check(path):
        begin = time.perf_counter()
        result = verify_msix(path, budget)
        digest = result.pop('archive_sha256', None)
        if digest is None:
            digest = file_hash(path)
        return {'path': str(path), 'sha256': digest, 'identity': package_identity(path),
                **result, 'seconds': round(time.perf_counter()-begin, 3)}
    return [check(path) for path in paths]


def verify_scope(source, output, workers=4):
    """Parallel full-file comparison of the copied package; no skipped payloads."""
    def inventory(root):
        result = {}
        for folder, dirs, files in os.walk(root):
            for name in dirs + files:
                p = Path(folder) / name
                if p.is_symlink() or getattr(p.stat(), 'st_file_attributes', 0) & 0x400:
                    raise ValueError('Reparse/link entry refused: ' + str(p))
            for name in files:
                p = Path(folder) / name
                rel = p.relative_to(root).as_posix()
                result[rel] = p
        return result
    a, b = inventory(Path(source)), inventory(Path(output))
    removed = {'AppxSignature.p7x', 'AppxBlockMap.xml', 'AppxMetadata/CodeIntegrity.cat'}
    changed = {'AppxManifest.xml', 'app/ChatGPT.exe', 'app/resources/app.asar'}
    if set(a)-set(b) != removed or set(b)-set(a):
        raise ValueError('Unexpected added/removed package files')
    def compare(name):
        return name if file_hash(a[name]) != file_hash(b[name]) else None
    with ThreadPoolExecutor(max_workers=worker_count(workers)) as pool:
        actual = {name for name in pool.map(compare, sorted(b)) if name}
    if actual != changed:
        raise ValueError('Unexpected package content changes: ' + repr(sorted(actual)))
    return {'files_compared': len(b), 'changed': sorted(actual), 'removed': sorted(removed),
            'workers': worker_count(workers)}


def copy_verified(source, destination, expected_sha256):
    """Hash exactly the bytes copied, in one source read; never overwrite an output."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError('Signed output must be a separate new file')
    digest = hashlib.sha256()
    # Exclusive creation also rejects a destination created after path validation.
    with source.open('rb') as reader, destination.open('xb') as writer:
        for data in iter(lambda: reader.read(8 * 1024 * 1024), b''):
            digest.update(data)
            writer.write(data)
    if digest.hexdigest().lower() != expected_sha256.lower():
        raise ValueError('Unsigned artifact hash mismatch before signing')


def sign_packages(plan_path, workers=2):
    """Sequential verified copies for HDDs, then bounded independent signers."""
    budget = min(2, worker_count(workers))
    plan = json.loads(Path(plan_path).read_text(encoding='utf-8-sig'))
    jobs = plan['jobs']
    sources = {Path(job['source']).resolve() for job in jobs}
    destinations = [Path(job['destination']).resolve() for job in jobs]
    if len(set(destinations)) != len(destinations) or sources.intersection(destinations):
        raise ValueError('Signed outputs must be distinct from all input/output files')
    if any(path.exists() for path in destinations):
        raise ValueError('Signed output must be a separate new file')
    start = time.perf_counter()
    for job in jobs:
        copy_verified(job['source'], job['destination'], job['sha256'])
    copy_seconds = round(time.perf_counter() - start, 3)
    # Do not compete with the source-copy workload on a mechanical disk.
    start = time.perf_counter()
    def sign(job):
        args = [plan['signtool'], 'sign', '/fd', 'SHA256', '/sha1', plan['thumbprint'], job['destination']]
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise ValueError('SignTool failed, exit ' + str(result.returncode))
        return job['destination']
    with ThreadPoolExecutor(max_workers=budget) as pool:
        outputs = list(pool.map(sign, jobs))
    return {'paths': outputs, 'copy_and_sha256_seconds': copy_seconds,
            'signtool_seconds': round(time.perf_counter() - start, 3), 'sign_workers': budget}


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


def verify_package_scope(source, package, mode='recovery'):
    """Bind every payload block to the original Store block map, without rereading GBs."""
    source = Path(source)
    def parse_xml(raw):
        if len(raw) > 64 * 1024 * 1024 or b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
            raise ValueError('Unsupported XML')
        return ET.fromstring(raw)
    def mapped(root):
        ns = '{http://schemas.microsoft.com/appx/2010/blockmap}'
        if root.tag != ns+'BlockMap' or root.get('HashMethod') != 'http://www.w3.org/2001/04/xmlenc#sha256':
            raise ValueError('Unsupported source block map')
        result = {}
        for file in root.findall(ns+'File'):
            name = file.attrib['Name'].replace('\\', '/').lower()
            if name in result:
                raise ValueError('Duplicate mapped file')
            result[name] = (int(file.attrib['Size']), tuple(b.attrib['Hash'] for b in file.findall(ns+'Block')))
        return result
    original = mapped(parse_xml((source/'AppxBlockMap.xml').read_bytes()))
    with zipfile.ZipFile(package) as z:
        copied = mapped(parse_xml(z.read('AppxBlockMap.xml')))
        target_manifest = parse_xml(z.read('AppxManifest.xml'))
    footprints = {'appxsignature.p7x', 'appxblockmap.xml', 'appxmetadata/codeintegrity.cat'}
    original = {k:v for k,v in original.items() if k not in footprints}
    if set(original) != set(copied):
        raise ValueError('Package payload set differs from original Store block map')
    actual = {k for k in original if original[k] != copied[k]}
    expected = {'appxmanifest.xml'}
    if mode == 'fast':
        expected.update(('app/chatgpt.exe', 'app/resources/app.asar'))
    elif mode != 'recovery':
        raise ValueError('Unsupported package scope mode')
    if actual != expected:
        raise ValueError('Unexpected block-map changes: ' + repr(sorted(actual)))
    original_manifest = parse_xml((source/'AppxManifest.xml').read_bytes())
    ns = '{http://schemas.microsoft.com/appx/manifest/foundation/windows10}'
    original_identity = original_manifest.find(ns+'Identity')
    version = list(map(int, original_identity.attrib['Version'].split('.')))
    version[-1] += 1 if mode == 'fast' else 2
    original_identity.set('Version', '.'.join(map(str, version)))
    def normalized(element):
        return (element.tag, sorted(element.attrib.items()), element.text if element.text and element.text.strip() else None,
                [normalized(child) for child in element])
    if normalized(original_manifest) != normalized(target_manifest):
        raise ValueError('Manifest changes exceed the version increment')
    return {'source_blockmap_entries': len(original), 'mode': mode, 'changed_payloads': sorted(actual),
            'manifest_only_version_changed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'patch', 'verify', 'launcher', 'msix', 'identity', 'packages', 'scope', 'hashes', 'sign', 'package-scope'])
    parser.add_argument('paths', nargs='+')
    parser.add_argument('--profile', type=Path)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--mode', choices=['fast', 'recovery'], default='recovery')
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text(encoding='utf-8-sig')) if args.profile else None
    if args.action in ('inspect', 'patch', 'verify') and not profile:
        parser.error('--profile is required')
    functions = {'inspect': lambda: inspect(*args.paths, profile), 'patch': lambda: patch_archive(*args.paths, profile, args.workers),
        'verify': lambda: verify_archive(*args.paths, profile, args.workers), 'launcher': lambda: repair_launcher(*args.paths),
        'msix': lambda: verify_msix(*args.paths, args.workers), 'identity': lambda: package_identity(*args.paths),
        'packages': lambda: verify_packages(args.paths, args.workers), 'scope': lambda: verify_scope(*args.paths, args.workers),
        'hashes': lambda: hash_paths(args.paths, args.workers), 'sign': lambda: sign_packages(*args.paths, args.workers),
        'package-scope': lambda: verify_package_scope(*args.paths, args.mode)}
    print(json.dumps(functions[args.action](), indent=2))


if __name__ == '__main__':
    main()
