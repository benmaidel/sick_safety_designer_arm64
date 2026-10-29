# Safety Designer ARM64 Patcher

Reusable scripts for creating experimental Windows ARM64 installer copies from supported SICK Safety Designer release packages. It handles the main launcher and discovers its SICK component installers automatically. It never installs software in Windows and never edits the downloaded originals.

## Run it on your Mac

1. Keep the `scripts/` folder intact and double-click **scripts/Patch Safety Designer.command**.
2. Drag the downloaded Safety Designer folder, or its main setup EXE, into the Terminal prompt and press Return.

The tool creates a new folder beside the source installer, named `<installer name>_ARM64_Experimental`. It stops if that folder already exists; move the previous result or choose another output name. It prints the final location when every check has passed.

This package includes the unpacker and its libraries for **Apple Silicon Macs running macOS 26 or later**. It requires **Python 3.9 or later with the standard lzma module**; Python is already available on the Mac used to build and test this package. No network access, Homebrew installation, administrator privileges or Parallels access is required by the patching tool.

The Windows test launcher in a generated bundle is a separate file. Run that inside a disposable Windows VM snapshot, with the whole generated folder copied to a local Windows disk.

## Command-line usage

From the repository root:

```sh
python3 scripts/patch_safety_designer.py "/path/to/SafetyDesigner_V2026.01_Setup.exe"
```

Choose a different new output folder:

```sh
python3 scripts/patch_safety_designer.py "/path/to/download/folder" --output "/path/to/new/ARM64-bundle"
```

Inspect the main package without extracting or creating an output folder:

```sh
python3 scripts/patch_safety_designer.py "/path/to/setup.exe" --inspect
```

On another platform, supply a suitable installed unpacker with `--extractor /path/to/innoextract`. The bundled native unpacker is for macOS Apple Silicon only; the Python source uses the standard library. Cross-platform operation has not been validated here.

## What it changes

For supported x64-capable SICK Inno installers, the tool adds ARM64 to the allowed architecture mask and to 64-bit installation mode where x64 mode was enabled. It preserves the other architecture bits. It changes the main launcher's `INSTALLSETUPCOMPONENT` function to load the adjacent patched component installers instead of its embedded originals.

It rebuilds metadata checksums and updates loader offsets. Modified copies lose their original Authenticode signatures and are unsigned. Compressed application payloads and the embedded setup engine remain byte-identical to the originals. The tool verifies those facts before publishing the bundle.

The main archive still contains its original embedded prerequisite files, but the patched component dispatcher executes the adjacent component copies. Keep the output folder together. The tool copies SICK's accompanying licence file into the bundle.

## Future-release support and refusal rules

The supported on-disk format is **Inno Setup data 6.0.0 Unicode**, with its observed loader/header layout, **IFPS script format 23**, and SICK's named `INITCOMPONENTS` and `INSTALLSETUPCOMPONENT` functions. This includes the supplied 2025.03 and 2026.01 main installers. A compiler's displayed version can differ from its on-disk data-format identifier.

There is no fixed release number, original installer hash or component-count restriction in the tool. It reads the component list from the script, matches it against the extracted files, and finds the dispatch constant within the actual named function body.

It deliberately stops on unfamiliar format/layout versions, damaged checksums, changed dispatch expressions, missing/extra components, unsafe archive paths, a non-x64-capable component, or a deeper nested Inno installer that still excludes ARM64 or needs a 64-bit-mode patch. It cannot promise automatic compatibility with every future SICK release. If a future release stops, preserve the message and the `*-FAILED-*` diagnostic-log folder for review. Do not disable the checks or change version labels to force it through.

Existing output files are never overwritten. Successful bundles are published only after validation completes. Failed builds remove their temporary executable copies and retain diagnostic logs when available. A large build needs roughly four times the source installer's size plus 512 MiB of free disk space. Memory use is bounded; large EXEs are copied and hashed in chunks.

## What it does not fix

Drivers, driver catalogues, licensing, application safety checks, Microsoft prerequisites and CodeMeter are not relabelled or patched. The tool inspects deeper executable/driver payloads and recognized Inno helpers, but it cannot infer every possible check inside arbitrary EXEs or MSI custom actions.

Windows application emulation cannot make an x86/x64 kernel driver into an ARM64 driver. Do not disable driver-signature enforcement. The generated test launcher skips the optional CodeMeter installation using SICK's existing `/NOCODEMETER` option; it does not remove runtime licence requirements. It requires .NET Framework 4.8.1 and opens the vendor's interactive component-selection UI.

In the earlier, separate **2025.03 Windows ARM64 test**, all 29 component installers returned zero and the application reached a responsive start page. Six USB driver-helper runs nevertheless failed. The main wrapper also returned zero in an unattended invocation without installing its custom-selected components. Those results demonstrate why component logs and real application/device tests matter; they are not a compatibility guarantee for another release. The reusable tool performs static checks only.

## Output and validation

Each generated folder contains:

- The modified main installer and all discovered SICK component installers.
- `Start-ARM64-Test.cmd`, which verifies hashes and opens the vendor UI inside Windows.
- `ARM64-Patch-Report.md`, explaining changes and limitations.
- `patch-manifest.json`, with source/output hashes, masks, payload hashes and validation results.
- `nested-inventory.json`, listing inspected helper and driver payloads.
- `logs/`, with unpacker listings, extraction logs and full archive-integrity results.

Validation includes metadata/loader CRCs, decoded setup-engine CRC, exact nested-extraction coverage, source immutability, narrowly limited metadata differences, unchanged compressed application/engine bytes, and independent archive-integrity checks using innoextract. Successful static validation is not proof of device communication, simulation, correct safety information, or suitability for commissioning or safety verification. Honor SICK's system requirements and application warnings.

## Repository contents

- `scripts/patch_safety_designer.py`: command-line tool and build orchestration.
- `scripts/inno_arm64.py`: bounded format readers, validation and metadata patching.
- `scripts/Patch Safety Designer.command`: double-click Mac launcher.
- `scripts/tests/`: regression tests with generated fixtures; no SICK application binaries.
- `scripts/vendor/`: the unmodified Mac unpacker, its libraries, hashes and licence notices.

Downloaded installers, generated bundles, logs and machine-specific test evidence are not part of this repository.

## Tests and third-party components

Run the included regression tests:

```sh
python3 -m unittest discover -s scripts/tests -v
```

The included unpacker is **innoextract 1.9**, by Daniel Scharrer. Its SHA-256 and the hashes of its bundled Boost, liblzma and zstd dependencies are checked before use. Dependencies come from the locally verified Homebrew bottles/libraries used during the earlier investigation. No system libraries are replaced. See [dependency hashes](scripts/vendor/dependencies.json), [licence notices](scripts/vendor/licenses/), and [third-party acknowledgements](scripts/THIRD-PARTY.md) for provenance, acknowledgements and licence notices.
