"""Regression tests for corruption, precise edits, and refusing unknown inputs.

Fixtures are generated locally and contain no vendor application payloads.
Run: python3 -m unittest discover -s tests -v
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
import hashlib
import contextlib
import io
from pathlib import Path
from unittest.mock import patch as mock_patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inno_arm64 import (MAGIC, VERSION, STRINGS, PatchError, dispatcher, inspect,
                        patch, read_block, script_functions, write_block)
from patch_safety_designer import inspect_nested, resolve_input, safe_archive_paths, main, debug_directory


def string(data):
    return struct.pack('<I', len(data)) + data


def script_fixture(path='{tmp}\\', components=('Setup_Core.exe', 'Setup_NewModule.exe')):
    # A minimal IFPS directory sufficient for locating, not executing, function bodies.
    body = struct.pack('<I', len(path)) + path.encode('utf-16le')
    init = b''.join(struct.pack('<I', len(name)) + name.encode('utf-16le') + b'\0' for name in components)
    records = []
    for name in ('EXTRACTTEMPORARYFILE', 'EXPANDCONSTANT', 'EXEC'):
        records.append(b'\x03' + bytes((len(name),)) + name.encode() + string(b''))
    exported = []
    for name in ('INSTALLSETUPCOMPONENT', 'INITCOMPONENTS'):
        exported.append(b'\x02' + b'\0' * 8 + string(name.encode()) + string(b''))
    prefix = b'IFPS' + struct.pack('<6I', 23, 1, 5, 0, 0, 0) + b'\x05' + b'\0' * 4
    start = len(prefix) + sum(map(len, records + exported))
    for record, offset, length in ((exported[0], start, len(body)),
                                    (exported[1], start + len(body), len(init))):
        records.append(record[:1] + struct.pack('<II', offset, length) + record[9:])
    return prefix + b''.join(records) + body + init


def installer_fixture(path, allowed=4, mode64=4, certificate=False, code=b'', payload_files=None):
    fields = {'app_name': 'Test Safety Designer', 'app_id': 'Safety Designer',
              'publisher': 'SICK AG', 'code': code}
    raw = b''.join(string(value if isinstance(value, bytes) else value.encode('utf-16le'))
                   for value in (fields.get(name, '') for name in STRINGS))
    fixed = bytearray(149)
    struct.pack_into('<I', fixed, 32, len(payload_files or {}))
    raw += fixed + bytes((allowed, mode64)) + bytes(32)
    prefix = bytearray(4096)
    prefix[:2] = b'MZ'; struct.pack_into('<I', prefix, 60, 128)
    prefix[128:132] = b'PE\0\0'; struct.pack_into('<H', prefix, 152, 0x10b)
    prefix[2048:] = (b'ORIGINAL_APPLICATION_PAYLOAD_' * 100)[:2048]
    locations = bytearray()
    if payload_files:
        prefix = prefix[:2048]
        for contents in payload_files.values():
            offset = len(prefix) - 2048
            record = bytearray(74)
            struct.pack_into('<IIIQQQ', record, 0, 0, 0, offset, 0, len(contents), len(contents))
            record[36:56] = hashlib.sha1(contents).digest()
            locations.extend(record)
            prefix.extend(b'zlb\x1a' + contents)
    header_offset = len(prefix)
    tail = VERSION.ljust(64, b'\0') + write_block(raw) + write_block(locations or bytes(8))
    engine_offset = len(prefix) + len(tail)
    engine = b'MZ' + bytes(62)
    tail += write_block(engine)
    cert = len(prefix) + len(tail)
    if certificate:
        tail += bytes(16)
        struct.pack_into('<II', prefix, 152 + 128, cert, 16)
    table = MAGIC + struct.pack('<7I', 1, len(prefix) + len(tail), engine_offset,
                               len(engine), zlib.crc32(engine), header_offset, 2048)
    table += struct.pack('<I', zlib.crc32(table))
    prefix[1024:1024 + len(table)] = table
    path.write_bytes(prefix + tail)
    return path


class FixtureExtractor:
    """A tiny stored-chunk decoder for exercising output/debug lifecycle only.

    Real Inno unpacker round-trips are tested separately on the actual download.
    Synthetic fixtures contain no vendor script bytecode or application data.
    """
    def __init__(self, fail=False):
        self.fail = fail

    def listing(self, source, log):
        Path(log).write_text('fixture listing\n')
        return ['tmp/Setup_Core.exe'] if inspect(source)['counts'][8] else ['app/placeholder.txt']

    def extract(self, source, target, log, includes=()):
        Path(log).write_text('fixture extraction\n')
        meta = inspect(source)
        record = meta['locations']
        offset = struct.unpack_from('<I', record, 8)[0]
        size = struct.unpack_from('<Q', record, 20)[0]
        flags = struct.unpack_from('<H', record, 72)[0]
        if flags & (16 | 64 | 128):
            raise ValueError('Fixture decoder only supports unfiltered stored chunks')
        with Path(source).open('rb') as stream:
            stream.seek(meta['payload'] + offset)
            if stream.read(4) != b'zlb\x1a':
                raise ValueError('Incorrect chunk offset or magic')
            content = stream.read(size)
        if hashlib.sha1(content).digest() != record[36:56]:
            raise ValueError('Incorrect embedded checksum')
        folder = Path(target) / 'tmp'; folder.mkdir(parents=True)
        (folder / 'Setup_Core.exe').write_bytes(content)

    def test(self, source, log):
        Path(log).write_text('fixture integrity check\n')
        if self.fail:
            raise PatchError('Injected verifier failure')
        inspect(source)


class PatcherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_payload_source_and_engine_are_preserved(self):
        source = installer_fixture(self.root / 'original.exe', certificate=True)
        original = source.read_bytes()
        output = self.root / 'patched.exe'
        row = patch(source, output)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual((inspect(output)['allowed'], inspect(output)['mode64']), (20, 20))
        self.assertEqual(row['metadata_changed_bytes'], 2)
        self.assertTrue(row['payload_unchanged'] and row['setup_engine_unchanged'])
        self.assertEqual(output.read_bytes()[152 + 128:152 + 136], bytes(8))

    def test_repatch_is_idempotent(self):
        source = installer_fixture(self.root / 'source.exe')
        first, second = self.root / 'first.exe', self.root / 'second.exe'
        patch(source, first); row = patch(first, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(row['metadata_changed_bytes'], 0)

    def test_no_overwrite_or_self_patch(self):
        source = installer_fixture(self.root / 'source.exe')
        with self.assertRaises(PatchError):
            patch(source, source)
        target = self.root / 'existing.exe'; target.write_bytes(b'KEEP')
        with self.assertRaises(PatchError):
            patch(source, target)
        self.assertEqual(target.read_bytes(), b'KEEP')

    def test_unknown_format_rejected_even_with_python_optimized(self):
        source = installer_fixture(self.root / 'future.exe')
        data = source.read_bytes().replace(VERSION, VERSION.replace(b'6.0.0', b'6.3.0'))
        source.write_bytes(data)
        with self.assertRaises(PatchError):
            inspect(source)
        tool = Path(__file__).resolve().parents[1] / 'patch_safety_designer.py'
        result = subprocess.run([sys.executable, '-O', str(tool), str(source), '--inspect'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('Unsupported Inno data version', result.stderr)
        self.assertEqual(source.read_bytes(), data)

    def test_corrupt_metadata_and_engine_are_rejected(self):
        source = installer_fixture(self.root / 'source.exe')
        meta = inspect(source)
        data = bytearray(source.read_bytes()); data[meta['header'] + 64] ^= 1
        bad = self.root / 'bad.exe'; bad.write_bytes(data)
        with self.assertRaisesRegex(PatchError, 'checksum'):
            inspect(bad)
        data = bytearray(source.read_bytes()); data[meta['engine'] + 10] ^= 1; bad.write_bytes(data)
        with self.assertRaisesRegex(PatchError, 'checksum'):
            inspect(bad)

    def test_non_x64_component_is_not_relabelled(self):
        source = installer_fixture(self.root / 'x86.exe', allowed=2, mode64=0)
        with self.assertRaisesRegex(PatchError, 'x64-capable'):
            patch(source, self.root / 'out.exe')
        self.assertFalse((self.root / 'out.exe').exists())

    def test_deeper_restricted_installer_stops_build(self):
        source = installer_fixture(self.root / 'nested.exe')
        with self.assertRaisesRegex(PatchError, 'Deeper nested'):
            inspect_nested(source, 'Component/tmp/nested.exe')
        source = installer_fixture(self.root / 'unrestricted.exe', allowed=0, mode64=0)
        self.assertEqual(inspect_nested(source, 'nested.exe')['allowed'], 0)

    def test_dispatch_change_is_confined_and_count_is_dynamic(self):
        original = script_fixture()
        changed, names, redirected = dispatcher(original)
        self.assertEqual(names, ['Setup_Core.exe', 'Setup_NewModule.exe'])
        self.assertTrue(redirected)
        self.assertEqual(sum(a != b for a, b in zip(original, changed)), 3)
        self.assertEqual(dispatcher(changed)[0], changed)
        self.assertIn('INITCOMPONENTS', script_functions(changed))

    def test_changed_dispatch_contract_stops(self):
        with self.assertRaisesRegex(PatchError, 'path expression'):
            dispatcher(script_fixture('{unexpected}\\'))

    def test_archive_traversal_and_ambiguous_input_rejected(self):
        with self.assertRaises(PatchError):
            safe_archive_paths(' - "tmp/../../outside.exe" (12 B)')
        with self.assertRaises(PatchError):
            safe_archive_paths(' - "/absolute.exe" (12 B)')
        for name in ('SafetyDesigner_A_Setup.exe', 'SafetyDesigner_B_Setup.exe'):
            (self.root / name).write_bytes(b'MZ')
        with self.assertRaisesRegex(PatchError, 'Expected one'):
            resolve_input(str(self.root))

    def test_finder_dragged_path_with_spaces(self):
        folder = self.root / 'Download with spaces'
        folder.mkdir()
        exe = folder / 'SafetyDesigner_Future_Setup.exe'
        exe.write_bytes(b'MZ')
        escaped = str(folder).replace(' ', '\\ ')
        self.assertEqual(resolve_input(escaped), exe.resolve())
        self.assertEqual(resolve_input("'" + str(folder) + "'"), exe.resolve())

    def make_release(self):
        component = installer_fixture(self.root / 'original-component.exe')
        source = installer_fixture(self.root / 'SafetyDesigner_Test_Setup.exe',
                                   code=script_fixture(components=('Setup_Core.exe',)),
                                   payload_files={'Setup_Core.exe': component.read_bytes()})
        return source

    def invoke_tool(self, source, *options, fail=False):
        with mock_patch('patch_safety_designer.Extractor', return_value=FixtureExtractor(fail)), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main([str(source), *options])

    def test_default_publishes_only_prefixed_single_exe(self):
        source = self.make_release()
        before = source.read_bytes()
        existing = set(self.root.iterdir())
        self.assertEqual(self.invoke_tool(source), 0)
        output = source.with_name('patched_arm64_' + source.name)
        self.assertEqual(set(self.root.iterdir()) - existing, {output})
        self.assertTrue(output.is_file())
        self.assertEqual(source.read_bytes(), before)
        meta = inspect(output)
        self.assertEqual((meta['allowed'], meta['mode64']), (20, 20))
        pos, length = meta['fields']['code']
        self.assertEqual(meta['raw'][pos:pos + length], script_fixture(components=('Setup_Core.exe',)))
        self.assertFalse(debug_directory(output).exists())
        # The actual embedded child, not an adjacent file, must be ARM64-patched.
        decoded = self.root / 'decoded'
        FixtureExtractor().extract(output, decoded, self.root / 'decode.log')
        self.assertEqual(inspect(decoded / 'tmp/Setup_Core.exe')['allowed'], 20)

    def test_debug_retains_reports_but_no_component_sidecars(self):
        source = self.make_release()
        existing = set(self.root.iterdir())
        self.assertEqual(self.invoke_tool(source, '--debug'), 0)
        output = source.with_name('patched_arm64_' + source.name)
        debug = debug_directory(output)
        self.assertEqual(set(self.root.iterdir()) - existing, {output, debug})
        self.assertTrue((debug / 'patch-manifest.json').is_file())
        self.assertTrue((debug / 'logs').is_dir())
        self.assertFalse(list(debug.rglob('*.exe')))

    def test_failed_build_cleans_everything_by_default(self):
        source = self.make_release()
        existing = set(self.root.iterdir())
        self.assertEqual(self.invoke_tool(source, fail=True), 2)
        self.assertEqual(set(self.root.iterdir()), existing)

    def test_failed_debug_build_keeps_only_diagnostics(self):
        source = self.make_release()
        existing = set(self.root.iterdir())
        self.assertEqual(self.invoke_tool(source, '--debug', fail=True), 2)
        output = source.with_name('patched_arm64_' + source.name)
        debug = debug_directory(output)
        self.assertEqual(set(self.root.iterdir()) - existing, {debug})
        self.assertEqual(json.loads((debug / 'status.json').read_text())['status'], 'failed')
        self.assertFalse(list(debug.rglob('*.exe')))

    def test_inspect_with_debug_remains_read_only(self):
        source = self.make_release()
        existing = set(self.root.iterdir())
        self.assertEqual(self.invoke_tool(source, '--inspect', '--debug'), 0)
        self.assertEqual(set(self.root.iterdir()), existing)

    def test_existing_default_output_is_never_replaced(self):
        source = self.make_release()
        output = source.with_name('patched_arm64_' + source.name)
        output.write_bytes(b'EXISTING INSTALLER')
        existing = set(self.root.iterdir())
        self.assertEqual(self.invoke_tool(source), 2)
        self.assertEqual(output.read_bytes(), b'EXISTING INSTALLER')
        self.assertEqual(set(self.root.iterdir()), existing)

    def test_existing_debug_folder_is_never_replaced(self):
        source = self.make_release()
        output = source.with_name('patched_arm64_' + source.name)
        debug = debug_directory(output)
        debug.mkdir(); (debug / 'keep.txt').write_text('EXISTING DEBUG LOG')
        existing = set(self.root.iterdir())
        self.assertEqual(self.invoke_tool(source, '--debug'), 2)
        self.assertEqual((debug / 'keep.txt').read_text(), 'EXISTING DEBUG LOG')
        self.assertEqual(set(self.root.iterdir()), existing)


if __name__ == '__main__':
    unittest.main()
