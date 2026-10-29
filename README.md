# Safety Designer ARM64 Patcher

Create a standalone experimental ARM64 installer from a supported SICK Safety Designer download. The patcher preserves the original installer, patches the architecture settings in the main launcher and its SICK components, and embeds those patched components back into one EXE.

## Run on your Mac

Double-click **scripts/Patch Safety Designer.command**, drag the downloaded folder or main EXE into the Terminal prompt, and press Return.

By default, the only permanent output is a new installer beside the original:

```text
SafetyDesigner_V2026.01_Setup.exe
patched_arm64_SafetyDesigner_V2026.01_Setup.exe
```

No output bundle, debug folder, component sidecars, report or log is retained by default. Temporary extraction/build folders are removed when the process finishes, including on failure or cancellation. Existing files are never overwritten.

Keep the repository's `scripts/` folder intact. The included unpacker/libraries require **Apple Silicon and macOS 26 or later**. The Python code requires **Python 3.9+ with lzma**. The patching tool needs no network access, Homebrew installation, administrator privileges or Parallels connection. It does not install anything in Windows.

## Command-line usage

From the repository root:

```sh
python3 scripts/patch_safety_designer.py "/path/to/SafetyDesigner_V2026.01_Setup.exe"
```

A download folder containing one original `SafetyDesigner*_Setup.exe` also works. Already generated `patched_arm64_…` files are excluded from folder discovery.

Choose another output **EXE filename**, rather than an output directory:

```sh
python3 scripts/patch_safety_designer.py "/path/to/setup.exe" --output "/path/to/patched_arm64_custom.exe"
```

Inspect the main package without extracting or writing output:

```sh
python3 scripts/patch_safety_designer.py "/path/to/setup.exe" --inspect
```

On another platform, install a suitable `innoextract` or pass `--extractor /path/to/innoextract`. The bundled native binaries are for Apple Silicon macOS only. Other platforms have not been validated.

## Optional debug output

Add `--debug` to retain diagnostic information:

```sh
python3 scripts/patch_safety_designer.py "/path/to/SafetyDesigner_V2026.01_Setup.exe" --debug
```

This produces the same standalone EXE plus a sibling folder:

```text
patched_arm64_SafetyDesigner_V2026.01_Setup.exe
patched_arm64_SafetyDesigner_V2026.01_Setup_debug/
```

The debug folder contains `patch-manifest.json`, `nested-inventory.json`, `ARM64-Patch-Report.md`, `status.json`, unpacker/integrity logs, and a copy of the accompanying SICK licence file when present. It contains no temporary installers or component sidecars and is not needed to run the patched EXE. Diagnostic logs are also retained there when a build fails after staging starts. Existing debug folders are not overwritten. `--inspect` stays read-only even with `--debug`.

For the interactive Mac prompt with debugging enabled:

```sh
zsh "scripts/Patch Safety Designer.command" --debug
```

## What changes

The tool adds ARM64 to allowed architecture masks and to 64-bit installation mode where x64 mode was enabled. Other architecture bits are preserved. Patched SICK component EXEs are embedded inside the rebuilt main Inno container, where the original vendor flow extracts and launches them from its temporary directory. No external-file dispatch or additional Windows launcher is required.

The outer container uses Inno stored chunks with updated file locations, sizes and checksums. Its compressed metadata and loader offsets/checksums are rebuilt. The resulting EXE can be larger than the download because its outer payload is stored without recompression; the application archives inside child installers remain unchanged. Setup-engine content is preserved byte for byte. Modified installer copies are unsigned because their original Authenticode signatures cannot authenticate changed content.

Drivers, driver catalogues, application safety checks, licensing, Microsoft prerequisites and CodeMeter are not relabelled or patched. The original licence file remains beside the source; a copy is retained only in debug output.

## Supported formats and future releases

Support is limited to the observed **Inno Setup data 6.0.0 Unicode** layout, **IFPS script format 23**, SICK's `INITCOMPONENTS` / `INSTALLSETUPCOMPONENT` functions, and the 74-byte embedded-file location-record layout. This includes the supplied 2025.03 and 2026.01 main packages. A compiler's displayed version can differ from its data-format identifier.

There is no fixed release number, source installer hash or component count. The component list is discovered from the script and matched to extracted files. The tool stops on unfamiliar formats, changed dispatch expressions, damaged checksums, missing/extra payloads, unsafe archive paths, encrypted/spanned containers, unsupported offsets or deeper nested Inno installers requiring further architecture changes. It does not promise compatibility with every future release. Rerun with `--debug` to retain diagnostics; do not disable checks or change version labels to force an unsupported package through.

Allow roughly four times the source installer size plus 512 MiB of free space. Large EXEs are copied and hashed in chunks. The current rebuild requires stored-chunk start offsets below 2 GiB and a final file below 4 GiB; it stops if those limits would be exceeded.

## Validation and Windows testing

Before publishing the EXE, the tool checks metadata/loader CRCs, decoded setup-engine CRC, architecture settings, original-file hashes, unchanged child application archives and unchanged setup engines. Every patched component and the rebuilt outer archive undergo full innoextract integrity verification. The final EXE is then extracted again, and every embedded file is compared against its intended SHA-256. This confirms the patched components are actually embedded, rather than depending on adjacent files.

These are **static checks**, not proof of runtime compatibility. Take a disposable Windows 11 ARM VM snapshot, keep machinery disconnected, copy only the patched EXE to a local Windows disk, and test the normal vendor UI. Ensure .NET Framework 4.8.1 is available. SICK's existing `/NOCODEMETER` option can skip optional bundled CodeMeter installation; `/NORESTART` prevents automatic restart. Licence requirements remain in place.

The earlier, separate 2025.03 VM test reached a responsive application start page after all 29 component installers returned zero. Six USB driver-helper runs nevertheless failed. An unattended wrapper also returned zero without selecting its custom components. Those observations apply to that earlier installation method; they do not establish runtime compatibility of a newly rebuilt installer. Check actual component installation and helper logs instead of relying only on a parent exit code.

Windows application emulation does not convert x86/x64 kernel drivers into ARM64 drivers. Do not disable driver-signature enforcement. Device communication, simulation, correct safety information, commissioning and safety verification need separate assessment. Honor SICK's system requirements and application warnings.

## Repository and tests

- `scripts/patch_safety_designer.py`: CLI, orchestration, single-file publishing and optional diagnostics.
- `scripts/inno_arm64.py`: bounded format readers, metadata patches and embedded-container rebuild.
- `scripts/Patch Safety Designer.command`: double-click Mac entry point.
- `scripts/tests/`: regression tests with generated fixtures; no SICK application binaries.
- `scripts/vendor/`: unmodified Mac unpacker/libraries, hashes and licence notices.

Run the regression tests:

```sh
python3 -m unittest discover -s scripts/tests -v
```

Downloaded installers, generated EXEs, diagnostics and machine-specific test evidence are excluded from the repository. The unpacker is **innoextract 1.9**, by Daniel Scharrer. Its hash and bundled dependency hashes are checked before execution. No system libraries are replaced. See [dependency hashes](scripts/vendor/dependencies.json), [licence notices](scripts/vendor/licenses/), and [third-party acknowledgements](scripts/THIRD-PARTY.md).
