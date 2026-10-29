#!/usr/bin/env python3
"""Create experimental ARM64-admitting copies of supported SICK installers."""
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

from inno_arm64 import MAGIC, PatchError, digest, dispatcher, inspect, patch, require

HERE = Path(__file__).resolve().parent
TOOL_VERSION = '1.0.0'


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
                      and re.fullmatch(r'SafetyDesigner.*_Setup\.exe', p.name, re.I)]
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


def write_windows_launcher(folder):
    # An inline PowerShell command avoids changing PowerShell execution policy.
    command = (
        "$ErrorActionPreference='Stop'; try { $root=$env:SD_ARM64_ROOT; "
        "$native=$env:PROCESSOR_ARCHITEW6432; if(-not $native){$native=$env:PROCESSOR_ARCHITECTURE}; "
        "if($native -ne 'ARM64'){throw 'This experimental launcher requires Windows ARM64.'}; "
        "$key=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,"
        "[Microsoft.Win32.RegistryView]::Registry64).OpenSubKey('SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full'); "
        "if(-not $key -or [int]$key.GetValue('Release',0) -lt 533320){throw 'Install or enable .NET Framework 4.8.1 before testing.'}; "
        "$manifest=Get-Content -LiteralPath (Join-Path $root 'patch-manifest.json') -Raw | ConvertFrom-Json; "
        "Write-Host 'Checking installer hashes...'; foreach($item in $manifest.files){ "
        "if((Get-FileHash -LiteralPath (Join-Path $root $item.output) -Algorithm SHA256).Hash -ne $item.output_sha256)"
        "{throw ('Missing or changed installer: '+$item.output)} }; "
        "$logs=Join-Path $env:TEMP ('SafetyDesigner-ARM64-'+(Get-Date -Format 'yyyyMMdd-HHmmss')); "
        "New-Item -ItemType Directory -Path $logs | Out-Null; Write-Host ('Logs: '+$logs); "
        "$log='/LOG='+[char]34+(Join-Path $logs 'Setup.log')+[char]34; "
        "$p=Start-Process -FilePath (Join-Path $root $manifest.main_output) "
        "-ArgumentList @('/NOCODEMETER','/NORESTART',$log) -Wait -PassThru; "
        "Write-Host ('Installer exit code: '+$p.ExitCode); exit $p.ExitCode "
        "} catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }"
    )
    text = ('@echo off\nsetlocal\nset "SD_ARM64_ROOT=%~dp0"\n'
            'echo Experimental ARM64 installer: use a disposable VM snapshot with machinery disconnected.\n'
            'echo This opens the vendor UI. Select components in that UI. USB driver steps can fail.\n'
            'powershell.exe -NoProfile -Command "' + command + '"\n'
            'set "SD_RESULT=%ERRORLEVEL%"\npause\nexit /b %SD_RESULT%\n')
    (folder / 'Start-ARM64-Test.cmd').write_bytes(text.replace('\n', '\r\n').encode('ascii'))


def write_report(folder, manifest, nested, prerequisites):
    title = manifest['product']
    lines = [f'# {title}: experimental ARM64 installer copies', '',
             'Created by Safety Designer ARM64 Patcher ' + TOOL_VERSION + '.', '',
             f"Source SHA-256: `{manifest['source_sha256']}`", '',
             f"Patched/verified {len(manifest['component_order'])} SICK component installers and the main launcher.", '',
             'The original files were opened for reading only; their hashes were checked again after processing. '
             'Modified copies are unsigned. Application payloads and embedded setup-engine content are unchanged.', '',
             'The main dispatcher now uses the adjacent patched component copies. Keep this entire folder together. '
             'Nested BUST helpers, Microsoft prerequisites, CodeMeter, drivers, licensing and application safety checks '
             'were not patched.', '', '## Changes', '',
             '| File | Allowed mask | 64-bit mode mask | Metadata bytes changed |',
             '|---|---|---|---|']
    for row in manifest['files']:
        lines.append(f"| {row['output']} | {row['architectures_allowed_before']:#04x} → "
                     f"{row['architectures_allowed_after']:#04x} | {row['mode64_before']:#04x} → "
                     f"{row['mode64_after']:#04x} | {row['metadata_changed_bytes']} |")
    lines.extend(['', '## Validation and limits', '',
                  'All output installers passed innoextract archive-integrity testing. Loader checksums, metadata '
                  'chunk checksums, the decoded setup-engine CRC, architecture masks, original-file hashes and '
                  'unchanged compressed payload/engine bytes were checked. These are static checks: this generated '
                  'bundle has not been installed or runtime-tested by the patcher.', '',
                  f'Inspected {len(nested)} extracted executable/driver/MSI payload instances inside components. '
                  'Recognized deeper Inno helpers were checked for ARM64 gates; an unsupported or restricted deeper '
                  'Inno installer would have stopped this build. Other executable/MSI custom actions may still have '
                  'checks that this tool cannot infer. See nested-inventory.json.', '',
                  'Windows ARM64 cannot run x86/x64 kernel drivers through application emulation. Do not rename '
                  'driver architecture labels or disable driver signature enforcement. A zero parent installer exit '
                  'code can hide a failed driver helper. In the separate 2025.03 VM test, six USB-helper runs failed '
                  'even though all component installers returned zero. That observation does not establish the '
                  'behavior of another release.', '',
                  'The previously tested vendor wrapper returned success in a silent run without installing its '
                  'custom-selected components. Use the normal UI through Start-ARM64-Test.cmd and verify actual '
                  'component installation; do not equate wrapper exit code zero with a complete installation.', '',
                  '## Windows test instructions', '',
                  '1. Take a disposable Windows 11 ARM VM snapshot; keep machinery disconnected.',
                  '2. Copy this entire folder to a local Windows disk.',
                  '3. Run Start-ARM64-Test.cmd. It requires .NET Framework 4.8.1, verifies the copied hashes, '
                  'opens the vendor selection UI, skips optional CodeMeter installation, and disables automatic restart.',
                  '4. Record component and driver errors. Restart Windows normally if required.',
                  '5. Test offline startup separately. Device communication, simulation, licensing-dependent features '
                  'and safety verification require their own assessment. Honor the application requirements/warnings.',
                  '6. Revert the VM snapshot if needed. The patcher never installs anything in Windows.', '',
                  'The main archive retains its original embedded prerequisite payloads. Unmodified prerequisites found:', ''])
    lines.extend('- ' + row['name'] for row in prerequisites)
    lines.extend(['', 'The complete source/output hashes and validation results are in patch-manifest.json. '
                  'No claim of SICK support or safety-related suitability is made by this installer experiment.', ''])
    (folder / 'ARM64-Patch-Report.md').write_text('\n'.join(lines), encoding='utf-8')


def build(source, destination, extractor):
    source, destination = source.resolve(), destination.resolve()
    require(not destination.exists(), 'Output already exists; choose a new folder: ' + str(destination))
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
            row = patch(component, stage / name)
            extractor.test(stage / name, logs / (name + '.integrity.log'))
            row['archive_integrity'] = 'passed'
            rows.append(row)
        main_name = source.stem + '_ARM64_Experimental.exe'
        print('Patching and verifying the main launcher...', flush=True)
        row = patch(source, stage / main_name, is_main=True)
        extractor.test(stage / main_name, logs / 'main-integrity.log')
        row['archive_integrity'] = 'passed'; rows.append(row)
        prerequisites = [{'name': p.name, 'sha256': digest(p), 'modified': False} for p in files
                         if p not in components.values()]
        require(digest(source) == source_hash, 'Source main installer changed during the build')
        manifest = {'schema': 1, 'tool_version': TOOL_VERSION,
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
        write_windows_launcher(stage)
        write_report(stage, manifest, nested, prerequisites)
        shutil.rmtree(work)
        require(not destination.exists(), 'Output folder appeared during the build; refusing to replace it')
        stage.rename(destination)
        print('\nReady: ' + str(destination), flush=True)
        print('Originals preserved. Static checks passed. Windows runtime compatibility is not established.', flush=True)
        return manifest
    except BaseException:
        # Only the uniquely named staging directory created above can be removed.
        failure = destination.parent / (destination.name + '-FAILED-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
        if stage.exists() and not failure.exists():
            # Preserve diagnostics, not a misleading incomplete installable bundle.
            if (stage / 'logs').exists():
                (stage / 'logs').rename(failure)
            shutil.rmtree(stage)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('installer', nargs='?', help='Main setup EXE or its download folder')
    parser.add_argument('-o', '--output', type=Path, help='New output folder; never overwritten')
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
                              'dispatcher_requires_redirect': redirect}, indent=2))
            return 0
        output = args.output or source.parent / (source.stem + '_ARM64_Experimental')
        build(source, output, Extractor(args.extractor))
        return 0
    except (PatchError, OSError, ValueError, EOFError) as error:
        print('\nSTOPPED: ' + str(error), file=sys.stderr)
        print('The original installer has not been modified. No completed bundle was published.', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('\nCancelled. Originals are unchanged.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
