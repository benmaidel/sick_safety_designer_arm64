# Third-party acknowledgements

The patcher Python code is a purpose-written, narrowly scoped implementation for this task. File-layout research used the locally inspected source of Inno Setup and innoextract, and the IFPS layout was cross-checked with binary-refinery. The CALL/JMP address-filter implementation follows Inno Setup's version-3 format so the embedded engine CRC can be validated; the Inno Setup licence notice is included.

Redistributed native components:

| Component | Version | Source | Notice |
|---|---|---|---|
| innoextract | 1.9, Homebrew revision 14 | https://constexpr.org/innoextract/ | vendor/licenses/innoextract-LICENSE.txt |
| Boost libraries | 1.92.0 | https://www.boost.org/ | vendor/licenses/Boost-LICENSE_1_0.txt |
| liblzma / XZ | 5.8.3 | https://tukaani.org/xz/ | vendor/licenses/xz-COPYING*.txt |
| zstd | 1.5.7 | https://facebook.github.io/zstd/ | vendor/licenses/zstd-LICENSE.txt and zstd-COPYING.txt |

Additional format reference: https://github.com/jrsoftware/issrc/tree/is-6_0_5 (notice: vendor/licenses/Inno-Setup-license.txt).

The native files are copied unmodified from the verified local analysis tools and installed libraries. Runtime search paths are supplied only to the unpacker process, using the libraries in this folder. This package does not redistribute SICK application binaries; those are read from the user's separately downloaded installer when generating a personal experimental bundle. SICK's own licence file is preserved in generated bundles.
