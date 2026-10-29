#!/usr/bin/env python3
"""Create one standalone patched_arm64 EXE from a supported SICK installer."""
import argparse
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import struct
import sys
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath

from inno_arm64 import MAGIC, PatchError, digest, dispatcher, inspect, patch, repack_main, require

HERE = Path(__file__).resolve().parent
TOOL_VERSION = '2.0.0'


def resolve_input(value):
    path = Path(value).expanduser()
    if not path.exists():
        try:
            words = shlex.split(value)
        except ValueError:
            words = []
        if len(words) == 1:
            path = Path(words[0]).expanduser()
    require(path.exists(), 'Input does not exist: ' + str(path))
    path = path.resolve()
    if path.is_dir():
        candidates = [p for p in path.iterdir() if p.is_file()
                      and re.fullmatch(r'SafetyDesigner.*_Setup\.exe', p.name, re.I)
                      and not p.name.lower().startswith('patched_arm64')]
        require(len(candidates) == 1,
                'Expected one SafetyDesigner*_Setup.exe in this folder; pass the exact EXE if ambiguous')
        path = candidates[0]
    require(path.suffix.lower() == '.exe', 'Pass the main Windows setup EXE or its download folder')
    return path


def safe_archive_paths(text):
    paths = re.findall(r'^\s*-\s+"([^"]+)"', text, re.M)
    require(paths, 'The unpacker did not return a recognizable archive file list')
    for value in paths:
        path = PurePosixPath(value.replace('\\', '/'))
        require(not path.is_absolute() and '..' not in path.parts and ':' not in value,
                'Unsafe path in installer archive: ' + value)
        require(not value.startswith(('/', '\\')), 'Absolute archive path is not supported')
    return list(dict.fromkeys(paths))


class Extractor:
    def __init__(self, explicit=None):
        self.env = os.environ.copy()
        self.env['LC_ALL'] = 'C'
        bundled = HERE / 'vendor/bin/innoextract'
        if explicit:
            self.path = Path(explicit).expanduser().resolve()
        elif platform.system() == 'Darwin' and platform.machine().lower() in ('arm64', 'aarch64'):
            manifest = json.loads((HERE / 'vendor/dependencies.json').read_text())
            for item in manifest['components']:
                file = HERE / 'vendor' / item['file']
                require(file.is_file() and digest(file) == item['sha256'],
                        'Bundled unpacker dependency is missing or changed: ' + item['file'])
            self.path = bundled
            self.env['DYLD_LIBRARY_PATH'] = str(HERE / 'vendor/lib')
        else:
            found = shutil.which('innoextract')
            require(found, 'This platform needs innoextract on PATH, or pass --extractor /path/to/innoextract')
            self.path = Path(found)
        require(self.path.is_file(), 'Unpacker not found: ' + str(self.path))
        result = subprocess.run([str(self.path), '--version'], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        require(result.returncode == 0 and 'innoextract' in result.stdout.lower(),
                'Cannot start innoextract: ' + result.stdout.strip())

    def run(self, source, log, *arguments):
        with Path(log).open('wb') as out:
            result = subprocess.run([str(self.path), *map(str, arguments), str(source)],
                                    env=self.env, stdout=out, stderr=subprocess.STDOUT)
        require(result.returncode == 0, 'Unpacker/verification failed for ' + Path(source).name
                + '; see ' + str(log))
        require(Path(log).stat().st_size < 32 * 1024 * 1024, 'Unexpectedly large unpacker log')
        return Path(log).read_text(encoding='utf-8', errors='replace')

    def listing(self, source, log):
        return safe_archive_paths(self.run(source, log, '--list'))

    def extract(self, source, target, log, includes=()):
        Path(target).mkdir(parents=True, exist_ok=True)
        arguments = ['--extract', '--silent', '--output-dir', str(target)]
        for include in includes:
            # Leading slash makes this an anchored virtual archive path filter.
            arguments.extend(['--include', '/' + include.lstrip('/')])
        self.run(source, log, *arguments)

    def test(self, source, log):
        self.run(source, log, '--test', '--silent')


def inspect_nested(path, virtual_path):
    """Inspect extracted helpers; do not silently overlook a deeper Inno gate."""
    with Path(path).open('rb') as stream:
        prefix = stream.read(2 * 1024 * 1024)
    row = {'file': virtual_path, 'sha256': digest(path), 'bytes': Path(path).stat().st_size}
    if prefix[:2] == b'MZ' and len(prefix) >= 64:
        pe = struct.unpack_from('<I', prefix, 60)[0]
        if pe + 6 <= len(prefix) and prefix[pe:pe + 4] == b'PE\0\0':
            machine = struct.unpack_from('<H', prefix, pe + 4)[0]
            row['pe_machine'] = {0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'ARM64'}.get(machine, hex(machine))
    if Path(path).suffix.lower() == '.exe':
        if MAGIC in prefix:
            meta = inspect(path)
            row.update({'format': meta['format'], 'allowed': meta['allowed'], 'mode64': meta['mode64']})
            require(meta['allowed'] == 0 or meta['allowed'] & 16,
                    'Deeper nested Inno installer blocks ARM64: ' + virtual_path
                    + '. This tool cannot replace embedded payloads at that depth.')
            require(not (meta['mode64'] & 4 and not meta['mode64'] & 16),
                    'Deeper nested installer needs an ARM64 64-bit-mode change: ' + virtual_path)
        else:
            row['format'] = 'Executable; no supported Inno loader found; not modified'
    elif Path(path).suffix.lower() == '.inf':
        data = Path(path).read_bytes()
        text = data.decode('utf-16') if data.startswith((b'\xff\xfe', b'\xfe\xff')) else data.decode('utf-8', errors='replace')
        row.update({'format': 'Windows driver INF; not modified',
                    'explicit_ntarm64': bool(re.search(r'NTarm64', text, re.I))})
    else:
        row['format'] = 'Windows driver/MSI payload; not modified'
    return row


def debug_directory(destination):
    return destination.with_name(destination.stem + '_debug')


def retain_debug(stage, destination, status, error=None):
    """Retain diagnostics only when requested, never temporary installer copies."""
    require(not destination.exists(), 'Debug folder already exists: ' + str(destination))
    prepared = stage / '_debug'
    prepared.mkdir()
    if (stage / 'logs').exists():
        (stage / 'logs').rename(prepared / 'logs')
    for file in stage.iterdir():
        if file.is_file() and file.suffix.lower() != '.exe':
            shutil.copy2(file, prepared / file.name)
    (prepared / 'status.json').write_text(json.dumps({'status': status, 'error': error}, indent=2) + '\n')
    prepared.rename(destination)


def write_report(folder, manifest, nested, prerequisites):
    lines = [f"# {manifest['product']}: standalone ARM64 installer", '',
             f"Output: `{manifest['main_output']}`", '',
             'The patched component installers are embedded inside this single EXE. The vendor launcher '
             'extracts and executes them from its temporary directory; no adjacent component files are required.', '',
             'The outer payload was rebuilt as Inno stored chunks, with updated offsets, sizes and file checksums. '
             'The original setup engine is unchanged. Child application archives, prerequisites, drivers, licensing '
             'and application safety checks were not modified. Modified installer copies are unsigned.', '',
             f"Verified {len(manifest['component_order'])} patched component installers and the rebuilt main archive. "
             f'Inspected {len(nested)} deeper executable/driver payload instances. The final EXE was extracted again '
             'and every embedded file was checked against the intended SHA-256. These are static checks; '
             'Windows runtime compatibility remains untested for this build.', '',
             '## Changes', '', '| Installer | Allowed mask | 64-bit mode mask |', '|---|---|---|']
    for row in manifest['files']:
        lines.append(f"| {row['output']} | {row['architectures_allowed_before']:#04x} → "
                     f"{row['architectures_allowed_after']:#04x} | {row['mode64_before']:#04x} → {row['mode64_after']:#04x} |")
    lines.extend(['', '## Windows test', '',
                  'Take a disposable Windows 11 ARM VM snapshot and keep machinery disconnected. Copy only the '
                  'patched EXE to a local Windows disk, ensure .NET Framework 4.8.1 is available, and run the normal '
                  'vendor UI. Select the components there. Use /NOCODEMETER if the optional bundled runtime should '
                  'be skipped and /NORESTART to prevent automatic restart. Existing licensing requirements remain.', '',
                  'An unattended wrapper exit code of zero can mean only the release wrapper was installed. '
                  'Check component installation and helper logs. Driver helpers can fail while a parent installer '
                  'returns success. x86/x64 kernel drivers do not become ARM64 drivers through emulation. No '
                  'driver signature enforcement is disabled by this tool.', '',
                  'Device communication, simulation, safety verification and commissioning are unproven. Honor '
                  'SICK system requirements and application warnings. The original installer is preserved.', '',
                  '## Unmodified prerequisites', ''])
    lines.extend('- ' + row['name'] for row in prerequisites)
    lines.extend(['', 'See patch-manifest.json, nested-inventory.json, and logs/ for the detailed diagnostics. '
                  'This folder exists because --debug was requested.', ''])
    (folder / 'ARM64-Patch-Report.md').write_text('\n'.join(lines), encoding='utf-8')


def build(source, destination, extractor, debug=False):
    source, destination = source.resolve(), destination.resolve()
    require(not destination.exists(), 'Output already exists; choose a new installer filename: ' + str(destination))
    require(destination.suffix.lower() == '.exe', '--output must name an EXE file, not a folder')
    debug_path = debug_directory(destination)
    if debug:
        require(not debug_path.exists(), 'Debug folder already exists: ' + str(debug_path))
    require(destination != source and source not in destination.parents,
            'Output cannot replace or be inside the source executable')
    meta = inspect(source)
    require(meta['values']['app_id'] == 'Safety Designer' and meta['values']['publisher'] == 'SICK AG',
            'This is not a recognized SICK Safety Designer main installer')
    code_pos, code_size = meta['fields']['code']
    _, names, _ = dispatcher(meta['raw'][code_pos:code_pos + code_size])
    destination.parent.mkdir(parents=True, exist_ok=True)
    require(shutil.disk_usage(destination.parent).free >= source.stat().st_size * 4 + 512 * 1024 ** 2,
            'Not enough free space: allow roughly four times the installer size plus 512 MiB')
    source_hash = digest(source)
    stage = Path(tempfile.mkdtemp(prefix='.' + destination.name + '.building-', dir=destination.parent))
    try:
        work, logs = stage / '_work', stage / 'logs'
        work.mkdir(); logs.mkdir()
        parts = work / 'patched-components'
        parts.mkdir()
        print('Inspecting and extracting the main archive...', flush=True)
        main_paths = extractor.listing(source, logs / 'main-list.log')
        extractor.extract(source, work / 'main', logs / 'main-extract.log')
        extracted = list((work / 'main').rglob('*'))
        files = [path for path in extracted if path.is_file()]
        components = {}
        for name in names:
            matches = [path for path in files if path.name.lower() == name.lower()]
            require(len(matches) == 1, 'Missing or ambiguous component: ' + name)
            components[name] = matches[0]
        actual = {path.name.lower() for path in files if re.fullmatch(r'Setup_.*\.exe', path.name, re.I)}
        require(actual == {name.lower() for name in names},
                'Archive components differ from the script component list; this launcher needs review')
        rows, nested = [], []
        for index, name in enumerate(names, 1):
            print(f'[{index}/{len(names)}] Inspecting, patching and verifying {name}', flush=True)
            component = components[name]
            cm = inspect(component)
            require(cm['values']['publisher'] == 'SICK AG', 'Unexpected component publisher: ' + name)
            paths = extractor.listing(component, logs / (name + '.list.log'))
            selected = [p for p in paths if PurePosixPath(p).suffix.lower() in ('.exe', '.msi', '.sys', '.inf')]
            if selected:
                helper_dir = work / 'nested' / name
                extractor.extract(component, helper_dir, logs / (name + '.nested-extract.log'), selected)
                actual_helpers = {p.relative_to(helper_dir).as_posix().lower()
                                  for p in helper_dir.rglob('*') if p.is_file()}
                require(actual_helpers == {p.replace('\\', '/').lower() for p in selected},
                        'Nested extraction did not return exactly the requested payload files: ' + name)
                for helper in sorted(helper_dir.rglob('*')):
                    if helper.is_file():
                        nested.append(inspect_nested(helper, name + '/' + helper.relative_to(helper_dir).as_posix()))
            row = patch(component, parts / name)
            extractor.test(parts / name, logs / (name + '.integrity.log'))
            row['archive_integrity'] = 'passed'
            rows.append(row)
        main_name = destination.name
        print('Embedding patched components into the standalone installer...', flush=True)
        row = repack_main(source, stage / main_name, files,
                          {name: parts / name for name in names})
        extractor.test(stage / main_name, logs / 'main-integrity.log')
        row['archive_integrity'] = 'passed'
        print('Extracting the finished installer to verify all embedded payloads...', flush=True)
        verified = work / 'roundtrip'
        extractor.extract(stage / main_name, verified, logs / 'main-roundtrip.log')
        actual_files = [p for p in verified.rglob('*') if p.is_file()]
        require(len(actual_files) == len(row['embedded_files']), 'Rebuilt embedded-file count differs')
        for item in row['embedded_files']:
            matches = [p for p in actual_files if p.name == item['name']]
            require(len(matches) == 1 and digest(matches[0]) == item['sha256'],
                    'Embedded payload round-trip mismatch: ' + item['name'])
        row['embedded_roundtrip'] = 'passed'
        rows.append(row)
        prerequisites = [{'name': p.name, 'sha256': digest(p), 'modified': False} for p in files
                         if p not in components.values()]
        require(digest(source) == source_hash, 'Source main installer changed during the build')
        manifest = {'schema': 2, 'tool_version': TOOL_VERSION,
                    'created': datetime.now().astimezone().isoformat(),
                    'product': meta['values']['app_name'], 'source_name': source.name,
                    'source_sha256': source_hash, 'original_preserved': True,
                    'supported_layout': meta['format'], 'main_output': main_name,
                    'component_order': names, 'files': rows,
                    'runtime_tested': False, 'unmodified_embedded_prerequisites': prerequisites}
        (stage / 'nested-inventory.json').write_text(json.dumps(nested, indent=2) + '\n', encoding='utf-8')
        license_rows = []
        for license_file in source.parent.glob('SD_*_Licenses.*'):
            if license_file.is_file():
                original_hash = digest(license_file)
                shutil.copy2(license_file, stage / license_file.name)
                require(digest(license_file) == original_hash
                        and digest(stage / license_file.name) == original_hash,
                        'Licence file changed while it was being copied')
                license_rows.append({'name': license_file.name, 'sha256': original_hash,
                                     'original_preserved': True})
        manifest['license_files'] = license_rows
        (stage / 'patch-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        write_report(stage, manifest, nested, prerequisites)
        require(not destination.exists(), 'Output appeared during the build; refusing to replace it')
        if debug:
            retain_debug(stage, debug_path, 'validated')
        (stage / main_name).rename(destination)
        print('\nReady: ' + str(destination), flush=True)
        if debug:
            print('Debug information: ' + str(debug_path), flush=True)
        print('Originals preserved. Static checks passed. Windows runtime compatibility is not established.', flush=True)
        return manifest
    except BaseException as error:
        if debug and not debug_path.exists():
            try:
                retain_debug(stage, debug_path, 'failed', str(error))
                print('Debug information: ' + str(debug_path), file=sys.stderr)
            except (OSError, PatchError) as debug_error:
                print('Could not save debug information: ' + str(debug_error), file=sys.stderr)
        raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('installer', nargs='?', help='Main setup EXE or its download folder')
    parser.add_argument('-o', '--output', type=Path, help='New output EXE path; defaults to patched_arm64_<original name> beside the input')
    parser.add_argument('--debug', action='store_true', help='Keep logs and reports in a sibling <output stem>_debug folder')
    parser.add_argument('--extractor', help='Optional custom innoextract executable')
    parser.add_argument('--inspect', action='store_true', help='Inspect the main layout only; create no output')
    parser.add_argument('--version', action='version', version=TOOL_VERSION)
    args = parser.parse_args(argv)
    try:
        value = args.installer
        if not value:
            print('Drag the Safety Designer download folder or main EXE here, then press Return:')
            value = input('> ').strip()
        source = resolve_input(value)
        if args.inspect:
            meta = inspect(source)
            pos, size = meta['fields']['code']
            _, names, redirect = dispatcher(meta['raw'][pos:pos + size])
            print(json.dumps({'product': meta['values']['app_name'], 'format': meta['format'],
                              'architectures_allowed': meta['allowed'], 'mode64': meta['mode64'],
                              'component_count': len(names), 'components': names,
                              'component_dispatch': 'embedded temporary extraction',
                              'restore_embedded_dispatch': not redirect}, indent=2))
            return 0
        output = args.output or source.with_name('patched_arm64_' + source.name)
        build(source, output, Extractor(args.extractor), debug=args.debug)
        return 0
    except (PatchError, OSError, ValueError, EOFError) as error:
        print('\nSTOPPED: ' + str(error), file=sys.stderr)
        print('The original installer has not been modified. No new installer was published.', file=sys.stderr)
        if not args.debug:
            print('Rerun with --debug to retain diagnostic logs.', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('\nCancelled. Originals are unchanged.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
