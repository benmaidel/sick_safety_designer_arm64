"""Bounded readers and narrowly scoped patches for the observed Inno 6.0 format.

This module changes installer metadata, not executable application instructions.
Unsupported layouts raise PatchError. No correctness checks rely on Python assert.
"""
import hashlib
import lzma
import mmap
import struct
import zlib
from functools import lru_cache
from pathlib import Path

MAGIC = b'rDlPtS\xcd\xe6\xd7{\x0b*'
VERSION = b'Inno Setup Setup Data (6.0.0) (u)'
MAX_HEADER = 64 * 1024 * 1024
STRINGS = ('app_name app_versioned_name app_id copyright publisher publisher_url '
           'support_phone support_url updates_url version default_dir group_name '
           'base_filename uninstall_dir uninstall_name uninstall_icon mutex '
           'username organisation serial readme contact comments modify_path '
           'uninstall_registry uninstallable close_filter setup_mutex '
           'changes_environment changes_associations license info_before info_after code').split()


class PatchError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise PatchError(message)


def u32(data, pos):
    require(0 <= pos <= len(data) - 4, 'Truncated integer in installer metadata')
    return struct.unpack_from('<I', data, pos)[0]


def digest(path, start=0, length=None):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        stream.seek(start)
        while length is None or length > 0:
            chunk = stream.read(4 * 1024 * 1024 if length is None else min(length, 4 * 1024 * 1024))
            if not chunk:
                require(length in (None, 0), 'Unexpected end while hashing a file range')
                break
            h.update(chunk)
            if length is not None:
                length -= len(chunk)
    return h.hexdigest()


def read_block(data, pos):
    require(0 <= pos <= len(data) - 9, 'Truncated compressed-block header')
    crc, size, compressed = struct.unpack_from('<IIB', data, pos)
    require(compressed in (0, 1), 'Unknown metadata compression flag')
    require(zlib.crc32(data[pos + 4:pos + 9]) == crc, 'Metadata block-header checksum mismatch')
    require(0 < size <= MAX_HEADER and pos + 9 + size <= len(data), 'Invalid metadata block size')
    end = pos + 9 + size
    pos += 9
    parts = []
    while pos < end:
        require(end - pos >= 5, 'Truncated metadata chunk')
        crc = u32(data, pos)
        chunk = data[pos + 4:min(pos + 4100, end)]
        require(zlib.crc32(chunk) == crc, 'Metadata chunk checksum mismatch')
        parts.append(chunk)
        pos += 4 + len(chunk)
    payload = b''.join(parts)
    if compressed:
        require(len(payload) >= 6 and payload[0] < 225, 'Invalid LZMA properties')
        prop = payload[0]
        filters = [{'id': lzma.FILTER_LZMA1, 'lc': prop % 9,
                    'lp': (prop // 9) % 5, 'pb': prop // 45,
                    'dict_size': u32(payload, 1)}]
        require(filters[0]['dict_size'] <= MAX_HEADER, 'Excessive LZMA dictionary')
        try:
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
            payload = decoder.decompress(payload[5:], max_length=MAX_HEADER + 1)
        except lzma.LZMAError as error:
            raise PatchError('Cannot decode metadata: ' + str(error)) from error
        require(len(payload) <= MAX_HEADER, 'Decompressed metadata exceeds supported limit')
    return payload, end


def write_block(raw):
    filters = [{'id': lzma.FILTER_LZMA1, 'dict_size': 8 * 1024 * 1024, 'lc': 3, 'lp': 0, 'pb': 2}]
    compressed = b'\x5d' + struct.pack('<I', 8 * 1024 * 1024)
    compressed += lzma.compress(raw, format=lzma.FORMAT_RAW, filters=filters)
    chunks = []
    for pos in range(0, len(compressed), 4096):
        chunk = compressed[pos:pos + 4096]
        chunks.append(struct.pack('<I', zlib.crc32(chunk)) + chunk)
    body = b''.join(chunks)
    header = struct.pack('<IB', len(body), 1)
    return struct.pack('<I', zlib.crc32(header)) + header + body


@lru_cache(maxsize=4)
def setup_engine_crc(filtered):
    """Undo Inno's version-3 CALL/JMP address filter before checking its CRC."""
    data = bytearray(filtered)
    pos = 0
    limit = len(data) - 4
    while pos < limit:
        if data[pos] in (0xe8, 0xe9):
            pos += 1
            if data[pos + 3] in (0, 255):
                relative = int.from_bytes(data[pos:pos + 3], 'little') - ((pos + 4) & 0xffffff)
                if relative & 0x800000:
                    data[pos + 3] ^= 255
                data[pos:pos + 3] = (relative & 0xffffff).to_bytes(3, 'little')
            pos += 4
        else:
            pos += 1
    return zlib.crc32(data)


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, size):
        require(0 <= size <= len(self.data) - self.pos, 'Truncated compiled script')
        value = self.data[self.pos:self.pos + size]
        self.pos += size
        return value

    def integer(self):
        return struct.unpack('<I', self.read(4))[0]

    def byte(self):
        return self.read(1)[0]

    def string(self):
        return self.read(self.integer())


def script_functions(code):
    """Read IFPS 23 directory records, without executing or rewriting bytecode."""
    reader = Reader(code)
    require(reader.read(4) == b'IFPS', 'Missing IFPS script signature')
    version, types, functions = reader.integer(), reader.integer(), reader.integer()
    reader.read(12)
    require(version == 23 and 0 < types < 10000 and 0 < functions < 10000,
            'Unsupported compiled-script version or table size')
    for _ in range(types):
        tag = reader.byte()
        kind = tag & 127
        if kind in (0x19, 0x15):
            reader.string()
        elif kind == 0x1a:
            reader.read(16)
        elif kind in (0x17, 0x0c):
            reader.read(4)
        elif kind == 0x16:
            reader.read(12)
        elif kind == 0x0b:
            reader.read(4 * reader.integer())
        else:
            require(0 <= kind <= 0x1d, 'Unknown compiled-script type')
        if tag & 128:
            reader.string()
        require(reader.integer() == 0, 'Script type attributes are not supported')
    result = {}
    for index in range(functions):
        tag = reader.byte()
        require(tag & ~7 == 0, 'Unknown script-function flags')
        name, offset, size = '', 0, 0
        if tag & 1:
            name = reader.read(reader.byte()).decode('ascii')
            if tag & 2:
                reader.string()
        else:
            offset, size = reader.integer(), reader.integer()
            require(offset + size <= len(code), 'Script function extends outside the script')
            if tag & 2:
                name = reader.string().decode('ascii')
                reader.string()
        if tag & 4:
            require(reader.integer() == 0, 'Script function attributes are not supported')
        if name:
            require(name.upper() not in result, 'Duplicate script function name')
            result[name.upper()] = {'offset': offset, 'size': size, 'index': index}
    return result


def unicode_constants(body):
    """Find length-prefixed IFPS UTF-16 constants; return their text and positions."""
    import re
    result = []
    for match in re.finditer(rb'(?:[\x20-\x7e]\x00){2,}', body):
        text = match.group().decode('utf-16le')
        if match.start() >= 4 and u32(body, match.start() - 4) == len(text):
            result.append((text, match.start() - 4))
    return result


def dispatcher(code):
    functions = script_functions(code)
    require('INSTALLSETUPCOMPONENT' in functions and 'INITCOMPONENTS' in functions,
            'Unsupported SICK launcher: component-dispatch functions were not found')
    function = functions['INSTALLSETUPCOMPONENT']
    require(function['size'] > 0, 'Component dispatcher has no body')
    start, size = function['offset'], function['size']
    body = code[start:start + size]
    old = struct.pack('<I', 6) + '{tmp}\\'.encode('utf-16le')
    new = struct.pack('<I', 6) + '{src}\\'.encode('utf-16le')
    require((body.count(old), body.count(new)) in ((1, 0), (0, 1)),
            'Unsupported component path expression: expected one tmp/src constant in the dispatcher')
    # Require the known execution primitives in the import directory, too.
    for primitive in ('EXTRACTTEMPORARYFILE', 'EXPANDCONSTANT', 'EXEC'):
        require(primitive in functions, 'Missing expected dispatcher primitive: ' + primitive)
    init = functions['INITCOMPONENTS']
    import re
    names = [text for text, _ in unicode_constants(code[init['offset']:init['offset'] + init['size']])
             if re.fullmatch(r'Setup_[A-Za-z0-9_.-]+\.exe', text, re.I)]
    require(names and len(set(name.lower() for name in names)) == len(names),
            'No unique component installer list found in INITCOMPONENTS')
    patched = code[:start] + body.replace(old, new) + code[start + size:]
    return patched, names, bool(body.count(old))


def inspect(path):
    path = Path(path)
    require(path.is_file() and path.stat().st_size > 1024, 'Not a usable installer: ' + str(path))
    with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        require(data[:2] == b'MZ', 'Not a Windows executable')
        limit = min(len(data), 2 * 1024 * 1024)
        candidates, cursor = [], 0
        while True:
            candidate = data.find(MAGIC, cursor, limit)
            if candidate < 0:
                break
            cursor = candidate + 1
            if candidate + 44 <= len(data):
                header = u32(data, candidate + 32)
                payload = u32(data, candidate + 36)
                if (candidate + 44 <= payload < header < len(data)
                        and data[header:header + 21] == b'Inno Setup Setup Data'
                        and zlib.crc32(data[candidate:candidate + 40]) == u32(data, candidate + 40)):
                    candidates.append(candidate)
        require(len(candidates) == 1,
                'Unsupported installer: missing or ambiguous Inno loader directory')
        table = candidates[0]
        require(table + 44 <= len(data) and zlib.crc32(data[table:table + 40]) == u32(data, table + 40),
                'Inno loader-directory checksum mismatch')
        require(u32(data, table + 12) == 1, 'Unsupported Inno loader revision')
        header, payload, engine = u32(data, table + 32), u32(data, table + 36), u32(data, table + 20)
        require(u32(data, table + 16) <= len(data), 'Installer is truncated')
        require(0 < payload < header < engine < len(data), 'Unsupported embedded installer layout')
        identifier = data[header:header + 64].split(b'\0')[0]
        require(identifier == VERSION, 'Unsupported Inno data version: ' + repr(identifier))
        raw, first_end = read_block(data, header + 64)
        locations, second_end = read_block(data, first_end)
        require(second_end == engine, 'Setup engine is not immediately after the location table')
        engine_raw, engine_end = read_block(data, engine)
        require(len(engine_raw) == u32(data, table + 24) and setup_engine_crc(engine_raw) == u32(data, table + 28),
                'Embedded setup-engine checksum mismatch')
        pos, fields, values = 0, {}, {}
        for name in STRINGS:
            length = u32(raw, pos)
            require(length <= len(raw) - pos - 4, 'Truncated setup header string')
            fields[name] = (pos + 4, length)
            value = raw[pos + 4:pos + 4 + length]
            if name not in ('license', 'info_before', 'info_after', 'code'):
                require(length % 2 == 0, 'Invalid Unicode header string')
                values[name] = value.decode('utf-16le')
            pos += 4 + length
        arch = pos + 64 + 20 + 8 + 9 + 1 + 20 + 8 + 12 + 7
        require(arch + 2 <= len(raw), 'Truncated architecture fields')
        allowed, mode64 = raw[arch:arch + 2]
        require(allowed <= 31 and mode64 <= 31, 'Unknown architecture mask')
        pe = u32(data, 0x3c)
        require(data[pe:pe + 4] == b'PE\0\0' and pe + 24 + 144 <= len(data), 'Invalid PE header')
        optional = pe + 24
        require(struct.unpack_from('<H', data, optional)[0] == 0x10b, 'Only x86 Inno loaders are supported')
        security = optional + 96 + 4 * 8
        certificate, certificate_size = struct.unpack_from('<II', data, security)
        if certificate_size:
            require(certificate >= engine_end and certificate + certificate_size <= len(data),
                    'Invalid certificate range')
        return {'path': str(path), 'name': path.name, 'size': len(data), 'table': table,
                'header': header, 'payload': payload, 'engine': engine, 'first_end': first_end,
                'second_end': second_end, 'engine_end': engine_end, 'raw': raw, 'fields': fields,
                'locations': locations, 'counts': struct.unpack_from('<16I', raw, pos),
                'values': values, 'arch': arch, 'allowed': allowed, 'mode64': mode64,
                'optional': optional, 'security': security, 'certificate': certificate,
                'certificate_size': certificate_size, 'format': VERSION.decode()}


def copy_range(source, target, start, length):
    source.seek(start)
    while length:
        chunk = source.read(min(length, 4 * 1024 * 1024))
        require(chunk, 'Installer changed or became truncated during copying')
        target.write(chunk)
        length -= len(chunk)


def embedded_dispatcher(code):
    """Keep the vendor's temporary-file dispatch, including for older patched inputs."""
    dispatcher(code)  # Validate the known script contract before changing anything.
    function = script_functions(code)['INSTALLSETUPCOMPONENT']
    start, size = function['offset'], function['size']
    body = code[start:start + size]
    old = struct.pack('<I', 6) + '{tmp}\\'.encode('utf-16le')
    external = struct.pack('<I', 6) + '{src}\\'.encode('utf-16le')
    return code[:start] + body.replace(external, old) + code[start + size:]


def sha1_file(path):
    checksum = hashlib.sha1()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            checksum.update(chunk)
    return checksum.digest()


def repack_main(source, target, original_files, replacements):
    """Embed patched child EXEs using supported Inno stored chunks, not sidecars.

    Only this observed 74-byte location-record layout is supported. Existing
    application archives inside the child EXEs stay unchanged. Stored outer
    chunks avoid changing or reimplementing Inno's compression/address filters.
    """
    source, target = Path(source), Path(target)
    require(source.resolve() != target.resolve() and not target.exists(),
            'Refusing to overwrite a source or existing output installer')
    before = digest(source)
    meta = inspect(source)
    require(meta['values']['publisher'] == 'SICK AG' and meta['values']['app_id'] == 'Safety Designer',
            'Only the supported SICK release-package container can be rebuilt')
    require(meta['allowed'] == 0 or meta['allowed'] & 4, 'Main installer is not x64-capable')
    count = meta['counts'][8]
    locations = bytearray(meta['locations'])
    require(count > 0 and len(locations) == count * 74,
            'Unsupported embedded-file location-table layout')
    originals = {}
    for file in map(Path, original_files):
        key = (file.stat().st_size, sha1_file(file))
        require(key not in originals, 'Ambiguous embedded-file checksum mapping')
        originals[key] = file
    require(len(originals) == count, 'Embedded-file count does not match extracted payloads')
    rows, used = [], set()
    for index in range(count):
        pos = index * 74
        first, last = struct.unpack_from('<II', locations, pos)
        flags = struct.unpack_from('<H', locations, pos + 72)[0]
        require(first == last == 0 and not flags & 64 and not flags & ~0x7ff,
                'Spanned, encrypted or unfamiliar embedded-file flags are unsupported')
        key = (struct.unpack_from('<Q', locations, pos + 20)[0], bytes(locations[pos + 36:pos + 56]))
        require(key in originals and key not in used, 'Cannot map an embedded file to its original payload')
        used.add(key)
        original = originals[key]
        replacement = Path(replacements.get(original.name, original))
        rows.append((pos, flags, original, replacement))
    require(set(replacements) <= {file.name for file in originals.values()},
            'A replacement is not present in the original container')
    raw = bytearray(meta['raw'])
    allowed = meta['allowed'] | 16 if meta['allowed'] else 0
    mode64 = meta['mode64'] | 16 if meta['mode64'] & 4 else meta['mode64']
    raw[meta['arch']:meta['arch'] + 2] = bytes((allowed, mode64))
    code_pos, code_size = meta['fields']['code']
    raw[code_pos:code_pos + code_size] = embedded_dispatcher(bytes(raw[code_pos:code_pos + code_size]))
    embedded = []
    with source.open('rb') as original_stream, target.open('xb+') as out:
        copy_range(original_stream, out, 0, meta['payload'])
        for pos, flags, original, replacement in rows:
            offset = out.tell() - meta['payload']
            size = replacement.stat().st_size
            require(offset <= 0x7fffffff and out.tell() + size + 4 < 2 ** 32,
                    'Rebuilt payload exceeds supported Inno loader offsets')
            out.write(b'zlb\x1a')
            with replacement.open('rb') as payload:
                copy_range(payload, out, 0, size)
            struct.pack_into('<IIIQQQ', locations, pos, 0, 0, offset, 0, size, size)
            locations[pos + 36:pos + 56] = sha1_file(replacement)
            # The extracted file is raw: no compression or CALL/JMP filter remains.
            struct.pack_into('<H', locations, pos + 72, flags & ~(128 | 16))
            embedded.append({'name': original.name, 'sha256': digest(replacement),
                             'bytes': size, 'component_replaced': original.name in replacements})
        header_offset = out.tell()
        original_stream.seek(meta['header'])
        out.write(original_stream.read(64))
        out.write(write_block(raw)); out.write(write_block(locations))
        engine_offset = out.tell()
        copy_range(original_stream, out, meta['engine'], meta['engine_end'] - meta['engine'])
        final_size = out.tell()
        require(final_size < 2 ** 32, 'Rebuilt installer exceeds the supported 4 GiB limit')
        out.seek(meta['security']); out.write(bytes(8))
        out.seek(meta['optional'] + 64); out.write(bytes(4))
        original_stream.seek(meta['table']); table = bytearray(original_stream.read(44))
        struct.pack_into('<I', table, 16, final_size)
        struct.pack_into('<I', table, 20, engine_offset)
        struct.pack_into('<I', table, 32, header_offset)
        struct.pack_into('<I', table, 40, zlib.crc32(table[:40]))
        out.seek(meta['table']); out.write(table)
    result = inspect(target)
    require(result['raw'] == raw and result['locations'] == locations, 'Rebuilt container metadata differs')
    engine_hash = digest(source, meta['engine'], meta['engine_end'] - meta['engine'])
    require(digest(target, result['engine'], result['engine_end'] - result['engine']) == engine_hash,
            'Rebuilding changed the setup engine')
    require(digest(source) == before, 'Original installer changed during rebuilding')
    return {'source': source.name, 'output': target.name, 'source_sha256': before,
            'output_sha256': digest(target), 'output_bytes': target.stat().st_size,
            'architectures_allowed_before': meta['allowed'], 'architectures_allowed_after': allowed,
            'mode64_before': meta['mode64'], 'mode64_after': mode64,
            'metadata_changed_bytes': sum(a != b for a, b in zip(meta['raw'], raw)),
            'component_path_redirected': False, 'component_dispatch': 'embedded temporary extraction',
            'payload_unchanged': False, 'application_payloads_unchanged': True,
            'setup_engine_unchanged': True, 'setup_engine_sha256': engine_hash,
            'signature_removed': True, 'embedded_files': embedded, 'runtime_tested': False}


def patch(source, target, is_main=False):
    source, target = Path(source), Path(target)
    require(source.resolve() != target.resolve(), 'Source and output must be different files')
    require(not target.exists(), 'Refusing to overwrite: ' + str(target))
    before = digest(source)
    meta = inspect(source)
    require(meta['values']['publisher'] == 'SICK AG', 'Only SICK AG component installers are patched')
    require(meta['allowed'] == 0 or meta['allowed'] & 4, 'This is not an x64-capable SICK installer')
    raw = bytearray(meta['raw'])
    new_allowed = meta['allowed'] | 16 if meta['allowed'] else 0
    new_mode64 = meta['mode64'] | 16 if meta['mode64'] & 4 else meta['mode64']
    raw[meta['arch']:meta['arch'] + 2] = bytes((new_allowed, new_mode64))
    redirected = False
    if is_main:
        pos, size = meta['fields']['code']
        code, _, redirected = dispatcher(bytes(raw[pos:pos + size]))
        raw[pos:pos + size] = code
    changed = sum(a != b for a, b in zip(meta['raw'], raw))
    require(changed <= (5 if is_main else 2), 'Unexpected metadata changes')
    with source.open('rb') as original, target.open('xb+') as out:
        if not changed:
            copy_range(original, out, 0, meta['size'])
        else:
            keep = meta['size']
            if meta['certificate_size'] and meta['certificate'] + meta['certificate_size'] == keep:
                keep = meta['certificate']
            copy_range(original, out, 0, keep)
            new_header = out.tell()
            original.seek(meta['header'])
            out.write(original.read(64))
            out.write(write_block(raw))
            copy_range(original, out, meta['first_end'], meta['second_end'] - meta['first_end'])
            new_engine = out.tell()
            copy_range(original, out, meta['engine'], meta['engine_end'] - meta['engine'])
            final_size = out.tell()
            require(final_size < 2 ** 32, 'Installer exceeds the supported 4 GiB loader size')
            out.seek(meta['security']); out.write(b'\0' * 8)
            out.seek(meta['optional'] + 64); out.write(b'\0' * 4)
            original.seek(meta['table'])
            table = bytearray(original.read(44))
            struct.pack_into('<I', table, 16, final_size)
            struct.pack_into('<I', table, 20, new_engine)
            struct.pack_into('<I', table, 32, new_header)
            struct.pack_into('<I', table, 40, zlib.crc32(table[:40]))
            out.seek(meta['table']); out.write(table)
    result = inspect(target)
    require(result['raw'] == raw, 'Written metadata differs from the intended patch')
    require(result['allowed'] == 0 or result['allowed'] & 16, 'Output does not admit ARM64')
    if meta['mode64'] & 4:
        require(result['mode64'] & 16, 'Output would use the wrong installation mode on ARM64')
    require(result['payload'] == meta['payload'], 'Payload offset unexpectedly changed')
    payload_hash = digest(source, meta['payload'], meta['header'] - meta['payload'])
    require(digest(target, meta['payload'], meta['header'] - meta['payload']) == payload_hash,
            'Application payload changed')
    engine_hash = digest(source, meta['engine'], meta['engine_end'] - meta['engine'])
    require(digest(target, result['engine'], result['engine_end'] - result['engine']) == engine_hash,
            'Embedded setup-engine content changed')
    require(digest(source) == before, 'Source installer changed while it was being processed')
    return {'source': source.name, 'output': target.name, 'source_sha256': before,
            'output_sha256': digest(target), 'output_bytes': target.stat().st_size,
            'architectures_allowed_before': meta['allowed'], 'architectures_allowed_after': new_allowed,
            'mode64_before': meta['mode64'], 'mode64_after': new_mode64,
            'metadata_changed_bytes': changed, 'component_path_redirected': redirected,
            'payload_sha256': payload_hash, 'setup_engine_sha256': engine_hash,
            'payload_unchanged': True, 'setup_engine_unchanged': True,
            'signature_removed': bool(changed), 'runtime_tested': False}
